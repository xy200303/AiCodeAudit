from collections import deque
import os
import re

from config import C


COMMON_SECURITY_HINT_PATTERNS = {
    "input_sources": [
        r"\b(upload|file|filename|filepath|path|callback|redirect)\b",
    ],
    "dangerous_sinks": [
        r"\b(eval|exec)\b",
        r"\b(select|insert|update|delete)\b.*(\+|format\(|f\"|sprintf\()",
        r"\b(innerHTML|dangerouslySetInnerHTML|document\.write)\b",
    ],
    "safety_signals": [
        r"\b(whitelist|allowlist)\b",
        r"\b(parameterized|prepared|placeholder)\b",
    ],
    "validation_signals": [
        r"\b(validate|sanitize|escape|check|verify|guard|filter)\b",
        r"\b(auth|authorize|permission|acl|role|requiredLogin|requiredAuth)\b",
        r"\b(is_safe|safe_path|normalized|canonical)\b",
    ],
}


LANGUAGE_SECURITY_HINT_PATTERNS = {
    ".py": {
        "input_sources": [
            r"\brequest\.(args|form|json|values|files)\b",
            r"\b(input|sys\.argv|os\.environ|getenv)\b",
        ],
        "dangerous_sinks": [
            r"\b(subprocess\.(run|Popen|call)|os\.system)\b",
            r"\b(pickle\.load|pickle\.loads|yaml\.load)\b",
            r"\b(requests\.(get|post|request))\b",
            r"\b(open|Path\.open|read_text|write_text)\b",
            r"\b(sqlite3|pymysql|psycopg2|sqlalchemy)\b",
        ],
        "safety_signals": [
            r"\b(yaml\.safe_load|html\.escape|markupsafe\.escape)\b",
            r"\b(pathlib\.Path|resolve\(\))\b",
            r"\b(subprocess\.(run|Popen)\s*\(\s*\[)\b",
        ],
        "validation_signals": [
            r"\b(pydantic|validator|marshmallow|schema\.load)\b",
        ],
    },
    ".js": {
        "input_sources": [
            r"\b(req|request)\.(query|body|params|headers|files)\b",
            r"\b(process\.env|window\.location|document\.location)\b",
        ],
        "dangerous_sinks": [
            r"\b(child_process\.(exec|spawn|execSync))\b",
            r"\b(require\s*\(|import\s*\()\b",
            r"\b(fetch|axios\.(get|post|request))\b",
            r"\b(fs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream))\b",
        ],
        "safety_signals": [
            r"\b(path\.normalize|path\.resolve)\b",
            r"\b(DOMPurify|validator\.)\b",
        ],
        "validation_signals": [
            r"\b(zod|joi|yup|express-validator)\b",
        ],
    },
    ".ts": {
        "input_sources": [
            r"\b(req|request)\.(query|body|params|headers|files)\b",
            r"\b(process\.env)\b",
        ],
        "dangerous_sinks": [
            r"\b(child_process\.(exec|spawn|execSync))\b",
            r"\b(fetch|axios\.(get|post|request))\b",
            r"\b(fs\.(readFile|readFileSync|writeFile|writeFileSync))\b",
        ],
        "safety_signals": [
            r"\b(path\.normalize|path\.resolve)\b",
        ],
        "validation_signals": [
            r"\b(zod|joi|class-validator|nestjs\/common)\b",
        ],
    },
    ".java": {
        "input_sources": [
            r"\b(request\.getParameter|@RequestParam|@PathVariable|@RequestBody)\b",
            r"\b(System\.getenv|MultipartFile)\b",
        ],
        "dangerous_sinks": [
            r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b",
            r"\b(HttpURLConnection|RestTemplate|WebClient)\b",
            r"\b(FileInputStream|FileOutputStream|Files\.(read|write))\b",
            r"\b(Statement|createStatement|executeQuery|executeUpdate)\b",
        ],
        "safety_signals": [
            r"\b(PreparedStatement|@PreAuthorize|hasRole)\b",
            r"\b(Paths\.get|normalize\(\)|toRealPath\(\))\b",
        ],
        "validation_signals": [
            r"\b(@Valid|Validator|BindingResult)\b",
        ],
    },
    ".go": {
        "input_sources": [
            r"\b(r\.URL\.Query|FormValue|PostFormValue|ShouldBindJSON|BindJSON)\b",
            r"\b(os\.Getenv|c\.Param|c\.Query|c\.PostForm)\b",
        ],
        "dangerous_sinks": [
            r"\b(exec\.Command|sql\.DB|QueryRow|Query|Exec)\b",
            r"\b(http\.Get|http\.Post|client\.Do)\b",
            r"\b(os\.Open|os\.Create|ioutil\.ReadFile|os\.WriteFile)\b",
            r"\b(template\.HTML|text/template)\b",
        ],
        "safety_signals": [
            r"\b(html/template|filepath\.Clean|filepath\.Join)\b",
            r"\b(PrepareContext|QueryContext|ExecContext)\b",
        ],
        "validation_signals": [
            r"\b(validator\.New|ShouldBind|binding:)\b",
        ],
    },
    ".php": {
        "input_sources": [
            r"\b(_GET|_POST|_REQUEST|_FILES|_COOKIE|_SERVER|_ENV)\b",
        ],
        "dangerous_sinks": [
            r"\b(include|include_once|require|require_once)\b",
            r"\b(system|exec|shell_exec|passthru|proc_open)\b",
            r"\b(mysqli_query|query|exec|PDO)\b",
            r"\b(file_get_contents|fopen|fwrite|readfile)\b",
            r"\b(unserialize)\b",
        ],
        "safety_signals": [
            r"\b(PDO::prepare|prepare\s*\(|realpath|basename)\b",
        ],
        "validation_signals": [
            r"\b(filter_input|htmlspecialchars|preg_match)\b",
        ],
    },
    ".c": {
        "input_sources": [
            r"\b(argv|getenv|recv|read|fgets|scanf)\b",
        ],
        "dangerous_sinks": [
            r"\b(system|popen|execl|execv|sprintf|strcpy|strcat|gets)\b",
            r"\b(fopen|open|write|read)\b",
        ],
        "safety_signals": [
            r"\b(snprintf|strncpy|realpath)\b",
        ],
        "validation_signals": [
            r"\b(strlen|sizeof|strncmp|memcmp)\b",
        ],
    },
    ".cpp": {
        "input_sources": [
            r"\b(argv|getenv|recv|read|std::cin)\b",
        ],
        "dangerous_sinks": [
            r"\b(system|popen|sprintf|strcpy|strcat)\b",
            r"\b(std::ifstream|std::ofstream|fstream)\b",
        ],
        "safety_signals": [
            r"\b(snprintf|std::filesystem::canonical|std::array)\b",
        ],
        "validation_signals": [
            r"\b(std::regex|std::clamp|size\(\))\b",
        ],
    },
    ".cs": {
        "input_sources": [
            r"\b(Request\.(Query|Form|Body|Headers)|IFormFile)\b",
            r"\b(Environment\.GetEnvironmentVariable)\b",
        ],
        "dangerous_sinks": [
            r"\b(Process\.Start|SqlCommand|ExecuteReader|ExecuteNonQuery)\b",
            r"\b(File\.(ReadAllText|WriteAllText|OpenRead|OpenWrite))\b",
            r"\b(HttpClient\.(GetAsync|PostAsync|SendAsync))\b",
        ],
        "safety_signals": [
            r"\b(Path\.GetFullPath|Path\.Combine|SqlParameter)\b",
            r"\b(Authorize|RequireRole)\b",
        ],
        "validation_signals": [
            r"\b(ModelState\.IsValid|DataAnnotations|FluentValidation)\b",
        ],
    },
}


SECURITY_HINT_PATTERNS = {
    "input_sources": [
        *COMMON_SECURITY_HINT_PATTERNS["input_sources"],
    ],
    "dangerous_sinks": [
        *COMMON_SECURITY_HINT_PATTERNS["dangerous_sinks"],
    ],
    "safety_signals": [
        *COMMON_SECURITY_HINT_PATTERNS["safety_signals"],
    ],
    "validation_signals": [
        *COMMON_SECURITY_HINT_PATTERNS["validation_signals"],
    ],
}


def _collect_pattern_hits(text: str, patterns: list[str]) -> list[str]:
    hits = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            token = match.group(0).strip()
            if token and token not in hits:
                hits.append(token)
    return hits


def _merge_security_hint_patterns(extension: str) -> dict:
    merged = {key: list(patterns) for key, patterns in SECURITY_HINT_PATTERNS.items()}
    language_patterns = LANGUAGE_SECURITY_HINT_PATTERNS.get(extension.lower(), {})
    for key, patterns in language_patterns.items():
        merged.setdefault(key, [])
        merged[key].extend(patterns)
    return merged


def _get_extension_from_node(node_data) -> str:
    path = str(node_data.get("path", "") or "")
    return os.path.splitext(path)[1].lower()


def extract_security_hints(node_data) -> dict:
    text_parts = [
        str(node_data.get("source_name", "")),
        str(node_data.get("target_name", "")),
        str(node_data.get("desc", "")),
        str(node_data.get("source_code", "")),
    ]
    corpus = "\n".join(part for part in text_parts if part)
    patterns = _merge_security_hint_patterns(_get_extension_from_node(node_data))
    return {
        key: _collect_pattern_hits(corpus, patterns)
        for key, patterns in patterns.items()
    }


def get_security_hint_profile(node_data) -> dict:
    hints = extract_security_hints(node_data)
    return {
        "input_count": len(hints["input_sources"]),
        "sink_count": len(hints["dangerous_sinks"]),
        "validation_count": len(hints["validation_signals"]),
        "safety_count": len(hints["safety_signals"]),
        "has_input": bool(hints["input_sources"]),
        "has_sink": bool(hints["dangerous_sinks"]),
        "has_validation": bool(hints["validation_signals"]),
        "has_safety": bool(hints["safety_signals"]),
    }


def security_hint_score(node_data) -> int:
    hints = extract_security_hints(node_data)
    return (
        len(hints["input_sources"]) * 4
        + len(hints["dangerous_sinks"]) * 6
        + len(hints["validation_signals"]) * 2
        + len(hints["safety_signals"])
    )


def get_local_security_summary(graph, center_node, max_depth=2, max_nodes=12) -> dict:
    local_nodes = get_local_subgraph_nodes(graph, center_node, max_depth=max_depth, max_nodes=max_nodes)
    summary = {
        "input_nodes": 0,
        "sink_nodes": 0,
        "validation_nodes": 0,
        "safety_nodes": 0,
        "combined_risk_nodes": 0,
        "local_nodes": local_nodes,
    }
    for node in local_nodes:
        profile = get_security_hint_profile(graph.nodes[node])
        summary["input_nodes"] += int(profile["has_input"])
        summary["sink_nodes"] += int(profile["has_sink"])
        summary["validation_nodes"] += int(profile["has_validation"])
        summary["safety_nodes"] += int(profile["has_safety"])
        summary["combined_risk_nodes"] += int(profile["has_input"] and profile["has_sink"])
    return summary


def _format_hint_line(label: str, values: list[str]) -> str:
    if not values:
        return f"{label}:无"
    return f"{label}:{' | '.join(values[:8])}"


def _format_node(index, node_data):
    hints = extract_security_hints(node_data)
    return f"""<路径_{index}>
        源码路径:{node_data.get("path")}
        源码文件名称:{node_data.get("name")}
        调用代码单元名称:{node_data.get("source_name")}
        被调用代码单元名称:{node_data.get("target_name")}
        代码起止行:{node_data.get("start_code_line", 0)}-{node_data.get("end_code_line", 0)}
        当前代码源码:{node_data.get("source_code")}
        源码摘要描述:{node_data.get("desc")}
        {_format_hint_line("输入源线索", hints["input_sources"])}
        {_format_hint_line("危险点线索", hints["dangerous_sinks"])}
        {_format_hint_line("校验/鉴权线索", hints["validation_signals"])}
        {_format_hint_line("安全信号", hints["safety_signals"])}
        <路径_{index}>"""


def _node_priority(graph, node) -> int:
    node_data = graph.nodes[node]
    hints = extract_security_hints(node_data)
    has_input = int(bool(hints["input_sources"]))
    has_sink = int(bool(hints["dangerous_sinks"]))
    has_validation = int(bool(hints["validation_signals"]))
    has_safety = int(bool(hints["safety_signals"]))
    return (
        has_input * 120
        + has_sink * 160
        + has_validation * 70
        + has_safety * 50
        + security_hint_score(node_data) * 5
        + graph.in_degree(node)
        + graph.out_degree(node)
        + max(1, len(str(node_data.get("source_code", "")).splitlines()))
    )


def _path_hint_summary(graph, path) -> dict[str, int]:
    summary = {
        "input_sources": 0,
        "dangerous_sinks": 0,
        "validation_signals": 0,
        "safety_signals": 0,
    }
    for node in path:
        hints = extract_security_hints(graph.nodes[node])
        for key in summary:
            summary[key] += len(hints[key])
    return summary


def _path_priority(graph, path) -> int:
    hint_summary = _path_hint_summary(graph, path)
    has_input = int(hint_summary["input_sources"] > 0)
    has_sink = int(hint_summary["dangerous_sinks"] > 0)
    has_validation = int(hint_summary["validation_signals"] > 0)
    has_safety = int(hint_summary["safety_signals"] > 0)
    chain_completeness = has_input * 80 + has_sink * 100 + (has_input and has_sink) * 180
    missing_guard_bonus = (has_input and has_sink and not has_validation and not has_safety) * 140
    return (
        chain_completeness
        + missing_guard_bonus
        + hint_summary["dangerous_sinks"] * 40
        + hint_summary["input_sources"] * 25
        + hint_summary["validation_signals"] * 8
        + hint_summary["safety_signals"] * 5
        + len(path) * 10
        + sum(_node_priority(graph, node) for node in path)
    )


def _dedupe_paths(paths):
    seen = set()
    result = []
    for path in paths:
        signature = tuple(path)
        if signature in seen:
            continue
        seen.add(signature)
        result.append(path)
    return result


def _collect_directed_paths(graph, center_node, max_depth=2, reverse=False):
    traversal_graph = graph.reverse(copy=False) if reverse else graph
    paths_by_target = {}
    queue = deque([(center_node, [center_node], 0)])
    seen_depth = {center_node: 0}

    while queue:
        current, path, depth = queue.popleft()
        if depth >= max_depth:
            continue

        neighbors = list(traversal_graph.successors(current))
        neighbors.sort(key=lambda node: (-_node_priority(graph, node), str(node)))
        for neighbor in neighbors:
            next_depth = depth + 1
            best_depth = seen_depth.get(neighbor)
            if best_depth is not None and best_depth < next_depth:
                continue
            seen_depth[neighbor] = next_depth
            next_path = path + [neighbor]
            queue.append((neighbor, next_path, next_depth))
            if neighbor == center_node:
                continue
            normalized_path = list(reversed(next_path)) if reverse else next_path
            existing = paths_by_target.get(neighbor)
            if existing is None or _path_priority(graph, normalized_path) > _path_priority(graph, existing):
                paths_by_target[neighbor] = normalized_path

    paths = list(paths_by_target.values())
    paths.sort(key=lambda item: (-_path_priority(graph, item), str(item)))
    return paths


def get_ranked_audit_paths(graph, center_node, max_depth=2, max_paths=6):
    inbound_paths = _collect_directed_paths(graph, center_node, max_depth=max_depth, reverse=True)
    outbound_paths = _collect_directed_paths(graph, center_node, max_depth=max_depth, reverse=False)

    chain_candidates = []
    for path in inbound_paths:
        chain_candidates.append(("上游输入链", path))
    for path in outbound_paths:
        chain_candidates.append(("下游危险链", path))

    for inbound in inbound_paths[:max_paths]:
        for outbound in outbound_paths[:max_paths]:
            chain_candidates.append(("贯通调用链", inbound + outbound[1:]))

    deduped_candidates_map = {}
    for chain_type, path in chain_candidates:
        signature = tuple(path)
        existing = deduped_candidates_map.get(signature)
        current_priority = (
            _path_priority(graph, path),
            chain_type == "贯通调用链",
            chain_type == "下游危险链",
        )
        if existing is None:
            deduped_candidates_map[signature] = (chain_type, path, current_priority)
            continue
        if current_priority > existing[2]:
            deduped_candidates_map[signature] = (chain_type, path, current_priority)

    deduped_candidates = [(chain_type, path) for chain_type, path, _ in deduped_candidates_map.values()]

    deduped_candidates.sort(
        key=lambda item: (
            -_path_priority(graph, item[1]),
            item[0] != "贯通调用链",
            str(item[1]),
        )
    )
    return deduped_candidates[:max_paths]


def _build_dependency_branches(graph, root_node, max_depth=2, max_nodes=12, max_branches=3, direction="upstream"):
    visited = {root_node}
    ordered_nodes = []
    edges = []
    branches = []
    queue = deque([(root_node, [root_node], 0)])

    while queue and len(visited) < max_nodes:
        current, path, depth = queue.popleft()
        if depth >= max_depth:
            normalized_path = list(reversed(path)) if direction == "upstream" else list(path)
            branches.append({"direction": direction, "path": normalized_path})
            continue

        neighbors = (
            list(graph.predecessors(current))
            if direction == "upstream"
            else list(graph.successors(current))
        )
        neighbors.sort(key=lambda node: (-_node_priority(graph, node), str(node)))
        selected_neighbors = neighbors[:max_branches]
        if not selected_neighbors:
            normalized_path = list(reversed(path)) if direction == "upstream" else list(path)
            branches.append({"direction": direction, "path": normalized_path})
            continue

        for neighbor in selected_neighbors:
            edges.append((neighbor, current) if direction == "upstream" else (current, neighbor))
            next_path = path + [neighbor]
            if neighbor not in visited and len(visited) < max_nodes:
                visited.add(neighbor)
                ordered_nodes.append(neighbor)
                queue.append((neighbor, next_path, depth + 1))
            else:
                normalized_path = list(reversed(next_path)) if direction == "upstream" else list(next_path)
                branches.append({"direction": direction, "path": normalized_path})

    if not branches:
        branches.append({"direction": direction, "path": [root_node]})

    unique_branches = []
    seen = set()
    for branch in branches:
        signature = (branch["direction"], tuple(branch["path"]))
        if signature in seen:
            continue
        seen.add(signature)
        unique_branches.append(branch)

    unique_branches.sort(
        key=lambda branch: (-_path_priority(graph, branch["path"]), -len(branch["path"]), str(branch["path"]))
    )
    return {
        "nodes": ordered_nodes,
        "edges": edges,
        "branches": unique_branches,
    }


def build_dependency_tree(graph, root_node, max_depth=2, max_nodes=12, max_branches=3):
    upstream_budget = max(2, max_nodes // 2)
    downstream_budget = max(2, max_nodes - upstream_budget)

    upstream = _build_dependency_branches(
        graph,
        root_node,
        max_depth=max_depth,
        max_nodes=upstream_budget,
        max_branches=max_branches,
        direction="upstream",
    )
    downstream = _build_dependency_branches(
        graph,
        root_node,
        max_depth=max_depth,
        max_nodes=downstream_budget,
        max_branches=max_branches,
        direction="downstream",
    )

    ordered_nodes = [root_node]
    for node in upstream["nodes"] + downstream["nodes"]:
        if node not in ordered_nodes and len(ordered_nodes) < max_nodes:
            ordered_nodes.append(node)

    branch_candidates = upstream["branches"] + downstream["branches"]
    branch_candidates.sort(
        key=lambda branch: (
            -_path_priority(graph, branch["path"]),
            branch["direction"] != "upstream",
            -len(branch["path"]),
            str(branch["path"]),
        )
    )

    return {
        "root": root_node,
        "nodes": ordered_nodes,
        "edges": upstream["edges"] + downstream["edges"],
        "branches": branch_candidates,
        "upstream_branches": upstream["branches"],
        "downstream_branches": downstream["branches"],
    }


def get_global_ranked_dependency_trees(graph, max_depth=2, max_nodes=12, max_trees=60):
    tree_candidates = []
    for node in graph.nodes:
        node_data = graph.nodes[node]
        if not node_data.get("source_code"):
            continue
        tree = build_dependency_tree(
            graph,
            node,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_branches=max(1, getattr(C.project, "dependency_tree_max_branches", 3)),
        )
        tree_candidates.append(tree)

    deduped_trees = []
    seen = set()
    for tree in tree_candidates:
        signature = (
            tree["root"],
            tuple(tree["nodes"]),
            tuple(tuple(edge) for edge in tree["edges"]),
        )
        if signature in seen:
            continue
        seen.add(signature)
        deduped_trees.append(tree)

    deduped_trees.sort(
        key=lambda tree: (
            -sum(_node_priority(graph, node) for node in tree["nodes"]),
            -len(tree["branches"]),
            -len(tree["nodes"]),
            str(tree["root"]),
        )
    )
    return deduped_trees[:max_trees]


def _format_path_chain(index, graph, chain_type, path):
    names = []
    for node in path:
        node_data = graph.nodes[node]
        display_name = str(node_data.get("source_name") or node_data.get("target_name") or node)
        names.append(display_name)
    hint_summary = _path_hint_summary(graph, path)
    return (
        f"<调用链_{index}>\n"
        f"链路类型:{chain_type}\n"
        f"路径:{' -> '.join(names)}\n"
        f"输入源数量:{hint_summary['input_sources']}\n"
        f"危险点数量:{hint_summary['dangerous_sinks']}\n"
        f"校验信号数量:{hint_summary['validation_signals']}\n"
        f"安全信号数量:{hint_summary['safety_signals']}\n"
        f"<调用链_{index}>"
    )


def gen_text_from_path(graph, path):
    text_list = []
    for index, node in enumerate(path):
        text_list.append(_format_node(index, graph.nodes[node]))
    return "\n".join(text_list)


def _format_dependency_tree_summary(graph, tree, ranked_paths=None):
    root_data = graph.nodes[tree["root"]]
    profile = get_security_hint_profile(root_data)
    lines = [
        "<依赖上下文摘要>",
        f"根节点:{root_data.get('source_name') or root_data.get('target_name') or tree['root']}",
        f"根路径:{root_data.get('path', '')}",
        f"树节点数:{len(tree['nodes'])}",
        f"树边数:{len(tree['edges'])}",
        f"分支数:{len(tree['branches'])}",
        f"上游分支数:{len(tree.get('upstream_branches', []))}",
        f"下游分支数:{len(tree.get('downstream_branches', []))}",
        f"根节点输入源数量:{profile['input_count']}",
        f"根节点危险点数量:{profile['sink_count']}",
        f"根节点校验信号数量:{profile['validation_count']}",
        f"根节点安全信号数量:{profile['safety_count']}",
    ]
    for index, branch in enumerate(tree["branches"][:8]):
        branch_path = branch["path"]
        branch_direction = "上游分支" if branch["direction"] == "upstream" else "下游分支"
        branch_names = []
        for node in branch_path:
            node_data = graph.nodes[node]
            branch_names.append(str(node_data.get("source_name") or node_data.get("target_name") or node))
        lines.append(f"{branch_direction}_{index}:{' -> '.join(branch_names)}")
    if ranked_paths:
        lines.append(f"重点链路数:{len(ranked_paths)}")
        for index, (chain_type, path) in enumerate(ranked_paths):
            names = []
            for node in path:
                node_data = graph.nodes[node]
                names.append(str(node_data.get("source_name") or node_data.get("target_name") or node))
            hint_summary = _path_hint_summary(graph, path)
            lines.extend([
                f"<重点链路_{index}>",
                f"链路类型:{chain_type}",
                f"路径:{' -> '.join(names)}",
                f"输入源数量:{hint_summary['input_sources']}",
                f"危险点数量:{hint_summary['dangerous_sinks']}",
                f"校验信号数量:{hint_summary['validation_signals']}",
                f"安全信号数量:{hint_summary['safety_signals']}",
                f"<重点链路_{index}>",
            ])
    lines.append("<依赖上下文摘要>")
    return "\n".join(lines)


def gen_text_from_dependency_tree(graph, tree):
    max_focus_paths = max(1, getattr(C.project, "dependency_context_max_focus_paths", 6))
    ranked_paths = get_ranked_audit_paths(
        graph,
        tree["root"],
        max_depth=max(2, len(tree.get("branches", []))),
        max_paths=min(max_focus_paths, max(3, len(tree.get("branches", [])))),
    )
    text_list = [_format_dependency_tree_summary(graph, tree, ranked_paths=ranked_paths)]
    for index, node in enumerate(tree["nodes"]):
        text_list.append(_format_node(index, graph.nodes[node]))
    return "\n".join(text_list)


def get_local_subgraph_nodes(graph, center_node, max_depth=2, max_nodes=12):
    focus_path_limit = min(max_nodes, max(1, getattr(C.project, "dependency_context_max_focus_paths", 6)))
    ranked_paths = get_ranked_audit_paths(graph, center_node, max_depth=max_depth, max_paths=focus_path_limit)
    visited = set()
    ordered_nodes = []

    for _, path in ranked_paths:
        for node in path:
            if node in visited:
                continue
            visited.add(node)
            ordered_nodes.append(node)
            if len(ordered_nodes) >= max_nodes:
                return ordered_nodes

    if center_node not in visited:
        visited.add(center_node)
        ordered_nodes.append(center_node)

    queue = deque([(center_node, 0)])
    while queue and len(ordered_nodes) < max_nodes:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue

        neighbors = list(graph.predecessors(current)) + list(graph.successors(current))
        neighbors.sort(key=lambda node: (-_node_priority(graph, node), str(node)))
        for neighbor in neighbors:
            if neighbor in visited:
                continue
            visited.add(neighbor)
            ordered_nodes.append(neighbor)
            queue.append((neighbor, depth + 1))
            if len(ordered_nodes) >= max_nodes:
                break
    return ordered_nodes


def gen_text_from_local_subgraph(graph, center_node, max_depth=2, max_nodes=12):
    focus_path_limit = min(max_nodes, max(1, getattr(C.project, "dependency_context_max_focus_paths", 6)))
    ranked_paths = get_ranked_audit_paths(graph, center_node, max_depth=max_depth, max_paths=focus_path_limit)
    ordered_nodes = get_local_subgraph_nodes(
        graph,
        center_node,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    text_list = []
    if ranked_paths:
        text_list.append("<依赖上下文摘要>")
        for index, (chain_type, path) in enumerate(ranked_paths):
            text_list.append(_format_path_chain(index, graph, chain_type, path))
        text_list.append("<依赖上下文摘要>")
    for index, node in enumerate(ordered_nodes):
        text_list.append(_format_node(index, graph.nodes[node]))
    return "\n".join(text_list)
