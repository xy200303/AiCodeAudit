import asyncio
import hashlib
import os
import re
from collections import deque
from typing import List

import networkx as nx
from loguru import logger
from tqdm import tqdm

from audit import get_all_source_files_bfs, print_source_dir, scan_project_struct
from audit.agent import agent_1, agent_2
from audit.tool import (
    build_dependency_tree,
    gen_text_from_dependency_tree,
    gen_text_from_local_subgraph,
    get_global_ranked_dependency_trees,
    get_local_security_summary,
    get_local_subgraph_nodes,
    get_security_hint_profile,
    security_hint_score,
)
from config import C
from models import SourceFile
from prompt import build_agent_1_prompt, build_agent_2_prompt
from utils import (
    count_message_tokens,
    count_text_tokens,
    gen_graph_by_codeunits,
    get_available_text_token_budget,
    get_effective_max_input_tokens,
    write_file,
)


PASS_CONCLUSIONS = {"审计通过", "结构化审计通过结果", "审核通过"}


def _estimate_message_tokens(prompt: str, text: str) -> int:
    return count_message_tokens([
        {"role": "system", "content": prompt},
        {"role": "user", "content": text},
    ])


def _resolve_agent_1_chunk_token_size() -> int:
    effective_input_limit = get_effective_max_input_tokens()
    prompt_candidates = [build_agent_1_prompt(ext) for ext in C.project.source_file_ext] or [build_agent_1_prompt(".txt")]
    prompt_budget_candidates = [
        budget
        for budget in (get_available_text_token_budget(prompt) for prompt in prompt_candidates)
        if budget is not None
    ]
    if not prompt_budget_candidates:
        legacy_chunk_size = getattr(C.openai, "max_per_tokens", None)
        return legacy_chunk_size or 4096

    safe_chunk_size = min(prompt_budget_candidates)
    legacy_chunk_size = getattr(C.openai, "max_per_tokens", None)
    if legacy_chunk_size is not None:
        safe_chunk_size = min(safe_chunk_size, legacy_chunk_size)

    if effective_input_limit is not None:
        logger.warning(
            "模型 {} 的输入上限为 {} tokens，源码分片预算已自动计算为 {} tokens",
            C.openai.model,
            effective_input_limit,
            safe_chunk_size,
        )
    return safe_chunk_size


def _build_incomplete_audit_report(total_tasks: int, failed_tasks: int, threshold: float) -> str:
    failure_rate = (failed_tasks / total_tasks) if total_tasks else 0.0
    return (
        "<审计报告>\n"
        "<结论>审计不完整</结论>\n"
        "<统计>\n"
        f"总任务数: {total_tasks}\n"
        f"失败任务数: {failed_tasks}\n"
        f"失败率: {failure_rate:.2%}\n"
        f"阈值: {threshold:.2%}\n"
        "</统计>\n"
        "<说明>\n"
        "本次 Agent_2 审计阶段存在较高比例的大模型请求失败，当前结果不应视为“审计通过”。\n"
        "建议检查网络连通性、代理服务稳定性或降低并发后重新执行审计。\n"
        "</说明>\n"
        "</审计报告>"
    )


def _collect_payload_extensions(graph: nx.DiGraph, nodes: list[str]) -> list[str]:
    extensions = []
    for node in nodes:
        path = str(graph.nodes[node].get("path", "") or "")
        ext = os.path.splitext(path)[1].lower()
        if ext and ext not in extensions:
            extensions.append(ext)
    return sorted(extensions)


def _fit_agent_2_tree_payload(graph: nx.DiGraph, tree: dict):
    payload = gen_text_from_dependency_tree(graph, tree)
    extensions = _collect_payload_extensions(graph, tree["nodes"])
    prompt = build_agent_2_prompt(extensions)
    message_tokens = _estimate_message_tokens(prompt, payload)
    max_input_tokens = get_effective_max_input_tokens()
    if max_input_tokens is None or message_tokens <= max_input_tokens:
        return payload, message_tokens
    return None, None


def _tree_candidate_score(graph: nx.DiGraph, tree: dict) -> int:
    score = 0
    branch_bonus = 0
    input_count = 0
    sink_count = 0
    validation_count = 0
    safety_count = 0
    for node in tree["nodes"]:
        node_data = graph.nodes[node]
        profile = get_security_hint_profile(node_data)
        input_count += profile["input_count"]
        sink_count += profile["sink_count"]
        validation_count += profile["validation_count"]
        safety_count += profile["safety_count"]
        score += security_hint_score(node_data) * 5
        score += graph.in_degree(node) + graph.out_degree(node)
        score += max(1, len(str(node_data.get("source_code", "")).splitlines()))

    for branch in tree["branches"]:
        branch_path = branch["path"]
        branch_bonus += min(120, len(branch_path) * 15)
        if branch["direction"] == "downstream":
            branch_bonus += 20

    score += branch_bonus
    score += input_count * 25 + sink_count * 35 + validation_count * 8 + safety_count * 5
    if input_count > 0 and sink_count > 0:
        score += 200
    if input_count > 0 and sink_count > 0 and validation_count == 0 and safety_count == 0:
        score += 150
    return score


def _candidate_precheck_score(graph: nx.DiGraph, node: str) -> tuple[int, dict]:
    node_data = graph.nodes[node]
    profile = get_security_hint_profile(node_data)
    local_summary = get_local_security_summary(
        graph,
        node,
        max_depth=max(1, C.project.audit_context_depth),
        max_nodes=max(1, C.project.max_audit_nodes),
    )
    score = (
        profile["input_count"] * 8
        + profile["sink_count"] * 10
        + profile["validation_count"] * 3
        + profile["safety_count"] * 2
        + local_summary["input_nodes"] * 4
        + local_summary["sink_nodes"] * 5
        + local_summary["combined_risk_nodes"] * 12
        + min(6, graph.in_degree(node) + graph.out_degree(node))
    )
    return score, {"profile": profile, "local_summary": local_summary}


def _is_high_value_audit_candidate(graph: nx.DiGraph, node: str) -> tuple[bool, int]:
    score, context = _candidate_precheck_score(graph, node)
    profile = context["profile"]
    local_summary = context["local_summary"]
    threshold = max(1, getattr(C.project, "agent2_candidate_score_threshold", 12))

    has_direct_signal = profile["has_input"] or profile["has_sink"] or profile["has_validation"] or profile["has_safety"]
    has_local_risk_chain = (
        local_summary["combined_risk_nodes"] > 0
        or (local_summary["input_nodes"] > 0 and local_summary["sink_nodes"] > 0)
    )
    return has_direct_signal or has_local_risk_chain or score >= threshold, score


def _fit_agent_2_payload(graph: nx.DiGraph, center_node: str):
    max_depth = max(1, C.project.audit_context_depth)
    max_nodes = max(1, C.project.max_audit_nodes)

    for depth in range(max_depth, 0, -1):
        for node_limit in range(max_nodes, 0, -1):
            ordered_nodes = get_local_subgraph_nodes(
                graph,
                center_node,
                max_depth=depth,
                max_nodes=node_limit,
            )
            payload = gen_text_from_local_subgraph(
                graph,
                center_node,
                max_depth=depth,
                max_nodes=node_limit,
            )
            extensions = _collect_payload_extensions(graph, ordered_nodes)
            prompt = build_agent_2_prompt(extensions)
            message_tokens = _estimate_message_tokens(prompt, payload)
            max_input_tokens = get_effective_max_input_tokens()
            if max_input_tokens is None or message_tokens <= max_input_tokens:
                return payload, ordered_nodes, message_tokens
    return None, [], None


def calculate_project_hash(root_dir) -> str:
    hash_object = hashlib.sha256()
    queue = deque([root_dir])
    while queue:
        current = queue.popleft()
        for file in sorted(current.source_files, key=lambda item: item.path):
            hash_object.update(file.path.encode("utf-8"))
            hash_object.update(file.extension.encode("utf-8"))
            hash_object.update(file.source_code.encode("utf-8"))
        for sub_dir in sorted(current.source_dirs, key=lambda item: item.path):
            queue.append(sub_dir)
    return hash_object.hexdigest()


async def async_run_agent_1(source_file_list: List[SourceFile], out_file, batch_size=10):
    logger.info("Agent_1 开始执行，文件分片数: {}", len(source_file_list))
    batches = [source_file_list[i:i + batch_size] for i in range(0, len(source_file_list), batch_size)]
    res_list = []
    failed_count = 0
    for batch in tqdm(batches, total=len(batches), desc="Agent_1 执行中..."):
        tasks = [asyncio.create_task(agent_1(source_file)) for source_file in batch]
        result_list = await asyncio.gather(*tasks, return_exceptions=True)
        for result in result_list:
            if isinstance(result, Exception):
                failed_count += 1
                logger.warning("Agent_1 任务失败并已隔离: {}", result)
                continue
            if result is None:
                continue
            res_list.extend(result)

    graph = gen_graph_by_codeunits(res_list)
    nx.write_graphml(graph, out_file)
    logger.info("Agent_1 计算完毕，输出文件:{}，失败任务数:{}", out_file, failed_count)


def build_audit_payloads(graph: nx.DiGraph) -> List[str]:
    payload_candidates = []
    tree_payload_candidates = []
    prescreen_disabled = bool(getattr(C.project, "disable_agent2_candidate_prescreen", False))
    tree_dedup_disabled = bool(getattr(C.project, "disable_agent2_tree_payload_dedup", False))
    node_dedup_disabled = bool(getattr(C.project, "disable_agent2_node_payload_dedup", False))
    final_dedup_disabled = bool(getattr(C.project, "disable_agent2_final_payload_dedup", False))
    seen_payload_signatures = set()
    seen_context_signatures = set()
    seen_tree_signatures = set()
    skipped_oversize_count = 0
    skipped_prescreen_count = 0
    prescreened_nodes = []

    ranked_trees = get_global_ranked_dependency_trees(
        graph,
        max_depth=max(1, C.project.audit_context_depth),
        max_nodes=max(1, C.project.max_audit_nodes),
        max_trees=max(30, C.project.max_audit_nodes * 3),
    )
    for tree in ranked_trees:
        root_data = graph.nodes[tree["root"]]
        is_candidate, prescreen_score = _is_high_value_audit_candidate(graph, tree["root"])
        if not prescreen_disabled and not is_candidate:
            continue
        payload, message_tokens = _fit_agent_2_tree_payload(graph, tree)
        if not payload:
            continue
        payload_signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if not tree_dedup_disabled and payload_signature in seen_tree_signatures:
            continue
        if not tree_dedup_disabled:
            seen_tree_signatures.add(payload_signature)
        tree_payload_candidates.append({
            "payload": payload,
            "score": _tree_candidate_score(graph, tree) + prescreen_score,
            "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
            "root": root_data.get("source_name", tree["root"]),
        })

    for node in graph.nodes:
        node_data = graph.nodes[node]
        if not node_data.get("source_code"):
            continue

        is_candidate, prescreen_score = _is_high_value_audit_candidate(graph, node)
        prescreened_nodes.append((node, prescreen_score, is_candidate))
        if not prescreen_disabled and not is_candidate:
            skipped_prescreen_count += 1
            continue

        payload, local_nodes, message_tokens = _fit_agent_2_payload(graph, node)
        if not payload:
            skipped_oversize_count += 1
            logger.warning("Agent_2 上下文无法收缩到模型限制内，已跳过节点: {}", node)
            continue
        payload_signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if not node_dedup_disabled and payload_signature in seen_payload_signatures:
            continue

        center_signature = hashlib.sha256(
            "||".join([
                node_data.get("path", ""),
                node_data.get("source_name", ""),
                node_data.get("target_name", ""),
                node_data.get("desc", ""),
                node_data.get("source_code", ""),
                ",".join(sorted(local_nodes)),
            ]).encode("utf-8")
        ).hexdigest()
        if not node_dedup_disabled and center_signature in seen_context_signatures:
            continue

        if not node_dedup_disabled:
            seen_payload_signatures.add(payload_signature)
            seen_context_signatures.add(center_signature)
        payload_candidates.append({
            "payload": payload,
            "score": (
                security_hint_score(node_data) * 5 +
                graph.in_degree(node) +
                graph.out_degree(node) +
                len(local_nodes) * 2 +
                max(1, len(node_data.get("source_code", "").splitlines())) +
                prescreen_score
            ),
            "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
        })

    source_nodes = [node for node in graph.nodes if graph.nodes[node].get("source_code")]
    minimum_candidate_count = min(
        len(source_nodes),
        max(10, max(1, len(source_nodes) // 3)),
    )

    if not prescreen_disabled and len(payload_candidates) < minimum_candidate_count:
        prescreened_nodes.sort(key=lambda item: (-item[1], str(item[0])))
        logger.warning(
            "Agent_2 预筛选结果较严格，已自动放宽候选保留数量: current={} minimum={}",
            len(payload_candidates),
            minimum_candidate_count,
        )
        for node, prescreen_score, already_selected in prescreened_nodes:
            if len(payload_candidates) >= minimum_candidate_count:
                break
            if already_selected:
                continue
            node_data = graph.nodes[node]
            payload, local_nodes, message_tokens = _fit_agent_2_payload(graph, node)
            if not payload:
                continue
            payload_signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if not node_dedup_disabled and payload_signature in seen_payload_signatures:
                continue
            center_signature = hashlib.sha256(
                "||".join([
                    node_data.get("path", ""),
                    node_data.get("source_name", ""),
                    node_data.get("target_name", ""),
                    node_data.get("desc", ""),
                    node_data.get("source_code", ""),
                    ",".join(sorted(local_nodes)),
                ]).encode("utf-8")
            ).hexdigest()
            if not node_dedup_disabled and center_signature in seen_context_signatures:
                continue

            if not node_dedup_disabled:
                seen_payload_signatures.add(payload_signature)
                seen_context_signatures.add(center_signature)
            payload_candidates.append({
                "payload": payload,
                "score": (
                    security_hint_score(node_data) * 5 +
                    graph.in_degree(node) +
                    graph.out_degree(node) +
                    len(local_nodes) * 2 +
                    max(1, len(node_data.get("source_code", "").splitlines())) +
                    prescreen_score
                ),
                "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
            })

    tree_payload_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))
    payload_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))
    if not payload_candidates:
        logger.warning("Agent_2 预筛选后无候选节点，已回退为全量高分节点模式")
        for node in graph.nodes:
            node_data = graph.nodes[node]
            if not node_data.get("source_code"):
                continue
            payload, local_nodes, message_tokens = _fit_agent_2_payload(graph, node)
            if not payload:
                continue
            payload_candidates.append({
                "payload": payload,
                "score": (
                    security_hint_score(node_data) * 5
                    + graph.in_degree(node)
                    + graph.out_degree(node)
                    + len(local_nodes) * 2
                    + max(1, len(node_data.get("source_code", "").splitlines()))
                ),
                "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
            })
        payload_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))

    merged_candidates = tree_payload_candidates + payload_candidates
    merged_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))

    payloads = []
    seen_merged_payloads = set()
    for item in merged_candidates:
        signature = hashlib.sha256(item["payload"].encode("utf-8")).hexdigest()
        if not final_dedup_disabled and signature in seen_merged_payloads:
            continue
        if not final_dedup_disabled:
            seen_merged_payloads.add(signature)
        payloads.append(item["payload"])

    logger.info(
        "Agent_2 任务压缩完成，候选节点:{}，候选依赖树数:{}，预筛选跳过节点数:{}，去重后任务数:{}，超限跳过节点数:{}，预筛选关闭:{}，树去重关闭:{}，节点去重关闭:{}，最终去重关闭:{}",
        graph.number_of_nodes(),
        len(tree_payload_candidates),
        skipped_prescreen_count,
        len(payloads),
        skipped_oversize_count,
        prescreen_disabled,
        tree_dedup_disabled,
        node_dedup_disabled,
        final_dedup_disabled,
    )
    return payloads


def normalize_report_text(report: str) -> str:
    if report is None:
        return ""
    normalized = report.strip()
    if normalized == "结构化审计通过结果":
        return "<审计报告>\n<结论>审计通过</结论>\n</审计报告>"
    return normalized


def is_pass_only_report(report: str) -> bool:
    normalized = normalize_report_text(report)
    if not normalized:
        return True
    if "<文件>" in normalized and "<漏洞>" in normalized:
        return False
    if normalized == "<审计通过>":
        return True

    conclusion_matches = re.findall(r"<结论>\s*(.*?)\s*</结论>", normalized, flags=re.DOTALL)
    if conclusion_matches and all(match.strip() in PASS_CONCLUSIONS for match in conclusion_matches):
        return True
    return normalized in PASS_CONCLUSIONS


async def async_run_agent_2(graph: nx.DiGraph, out_file, batch_size=10):
    payloads = build_audit_payloads(graph)
    logger.info("Agent_2 开始执行，局部上下文任务数: {}", len(payloads))
    if not payloads:
        empty_report = "<审计报告>\n<结论>审计通过</结论>\n</审计报告>"
        write_file(out_file, empty_report)
        logger.warning("Agent_2 未生成可审计任务，已输出占位报告: {}", out_file)
        return

    batches = [payloads[i:i + batch_size] for i in range(0, len(payloads), batch_size)]
    reports = []
    failed_count = 0
    filtered_pass_count = 0
    total_tasks = len(payloads)
    failure_rate_threshold = max(0.0, min(1.0, getattr(C.project, "agent2_failure_rate_threshold", 0.3)))

    for batch in tqdm(batches, total=len(batches), desc="Agent_2 执行中..."):
        tasks = [asyncio.create_task(agent_2(payload)) for payload in batch]
        result_list = await asyncio.gather(*tasks, return_exceptions=True)
        for result in result_list:
            if isinstance(result, Exception):
                failed_count += 1
                logger.warning("Agent_2 任务失败并已隔离: {}", result)
                continue
            if result is None:
                continue
            normalized = normalize_report_text(result)
            if is_pass_only_report(normalized):
                filtered_pass_count += 1
                continue
            reports.append(normalized)
        write_file(
            out_file,
            "\n--------------------------------\n".join(reports)
            if reports
            else "<审计报告>\n<结论>审计通过</结论>\n</审计报告>",
        )

    failure_rate = (failed_count / total_tasks) if total_tasks else 0.0
    is_incomplete = failed_count > 0 and failure_rate >= failure_rate_threshold

    if is_incomplete:
        incomplete_report = _build_incomplete_audit_report(total_tasks, failed_count, failure_rate_threshold)
        final_report = incomplete_report
        if reports:
            final_report += "\n--------------------------------\n" + "\n--------------------------------\n".join(reports)
        write_file(out_file, final_report)
        logger.warning(
            "Agent_2 失败率过高，结果已标记为审计不完整: total_tasks={} failed_tasks={} failure_rate={:.2%} threshold={:.2%}",
            total_tasks,
            failed_count,
            failure_rate,
            failure_rate_threshold,
        )
    elif not reports and not os.path.exists(out_file):
        write_file(out_file, "<审计报告>\n<结论>审计通过</结论>\n</审计报告>")

    logger.info(
        "Agent_2 计算完毕，输出文件:{}，失败任务数:{}，失败率:{:.2%}，过滤通过结果数:{}，保留风险结果数:{}",
        out_file,
        failed_count,
        failure_rate,
        filtered_pass_count,
        len(reports),
    )


def run_audit(project_dir: str, output_dir: str, batch_size: int = 10):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    root_dir = scan_project_struct(project_dir)
    project_hash = calculate_project_hash(root_dir)
    logger.info("扫描完成，项目内容哈希: {}", project_hash)
    logger.debug("解析目录结构如下\n{}", print_source_dir(root_dir))

    graph_path = os.path.join(output_dir, f"{project_hash}.graphml")
    report_path = os.path.join(output_dir, f"{project_hash}_审计结果.log")

    if not os.path.exists(graph_path):
        source_file_list = get_all_source_files_bfs(root_dir, chunk_token_size=_resolve_agent_1_chunk_token_size())
        logger.info("调用异步处理 Agent_1...")
        asyncio.run(async_run_agent_1(source_file_list, out_file=graph_path, batch_size=batch_size))
    else:
        logger.info("项目依赖解析文件存在，直接跳过")

    logger.info("调用异步处理 Agent_2...")
    graph = nx.read_graphml(graph_path)
    asyncio.run(async_run_agent_2(graph, out_file=report_path, batch_size=batch_size))
    logger.success("输出成功，请在目录:{}查看", output_dir)

    return {
        "project_hash": project_hash,
        "graph_path": graph_path,
        "report_path": report_path,
        "output_dir": output_dir,
    }
