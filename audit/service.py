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
from audit.tool import gen_text_from_local_subgraph, get_local_subgraph_nodes, security_hint_score
from config import C
from models import SourceFile
from utils import count_text_tokens, gen_graph_by_codeunits, write_file


PASS_CONCLUSIONS = {"审计通过", "结构化审计通过结果", "审核通过"}


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
    seen_payload_signatures = set()
    seen_context_signatures = set()

    for node in graph.nodes:
        node_data = graph.nodes[node]
        if not node_data.get("source_code"):
            continue

        local_nodes = get_local_subgraph_nodes(
            graph,
            node,
            max_depth=C.project.audit_context_depth,
            max_nodes=C.project.max_audit_nodes,
        )
        payload = gen_text_from_local_subgraph(
            graph,
            node,
            max_depth=C.project.audit_context_depth,
            max_nodes=C.project.max_audit_nodes,
        )
        payload_signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if payload_signature in seen_payload_signatures:
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
        if center_signature in seen_context_signatures:
            continue

        seen_payload_signatures.add(payload_signature)
        seen_context_signatures.add(center_signature)
        payload_candidates.append({
            "payload": payload,
            "score": (
                security_hint_score(node_data) * 5 +
                graph.in_degree(node) +
                graph.out_degree(node) +
                len(local_nodes) * 2 +
                max(1, len(node_data.get("source_code", "").splitlines()))
            ),
            "tokens": count_text_tokens(payload),
        })

    payload_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))
    payloads = [item["payload"] for item in payload_candidates]
    logger.info(
        "Agent_2 任务压缩完成，候选节点:{}，去重后任务数:{}",
        graph.number_of_nodes(),
        len(payloads),
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

    if not reports and not os.path.exists(out_file):
        write_file(out_file, "<审计报告>\n<结论>审计通过</结论>\n</审计报告>")

    logger.info(
        "Agent_2 计算完毕，输出文件:{}，失败任务数:{}，过滤通过结果数:{}，保留风险结果数:{}",
        out_file,
        failed_count,
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
        source_file_list = get_all_source_files_bfs(root_dir, chunk_token_size=C.openai.max_per_tokens)
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
