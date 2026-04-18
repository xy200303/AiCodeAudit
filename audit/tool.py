from collections import deque
import re


SECURITY_HINT_PATTERNS = {
    "input_sources": [
        r"\brequest\.(args|form|json|values)\b",
        r"\b(req|request)\.(query|body|params)\b",
        r"\b(getParameter|FormValue|URL\.Query|input)\b",
        r"\b(os\.environ|process\.env|getenv|Request\.(Query|Form|Body))\b",
        r"\b(_GET|_POST|_REQUEST|_FILES|_ENV)\b",
        r"\b(upload|file|filename|filepath|path)\b",
    ],
    "dangerous_sinks": [
        r"\b(eval|exec)\b",
        r"\b(subprocess\.(run|Popen|call)|os\.system|Process\.Start|Runtime\.getRuntime\(\)\.exec|child_process\.(exec|spawn))\b",
        r"\b(system|popen|ProcessBuilder|exec\.Command)\b",
        r"\b(select|insert|update|delete)\b.*(\+|format\(|f\")",
        r"\b(include|require|require_once|import_module|load)\b",
        r"\b(open|read|write|File|FileInputStream|FileOutputStream|fs\.)\b",
        r"\b(requests\.(get|post)|http\.Get|fetch|axios\.)\b",
        r"\b(innerHTML|dangerouslySetInnerHTML|document\.write)\b",
        r"\b(pickle\.load|pickle\.loads|yaml\.load|unserialize)\b",
    ],
    "safety_signals": [
        r"\b(PreparedStatement|parameterized|placeholders?)\b",
        r"\bexecute\s*\([^)]*[,?]\s*[\w\[\{]",
        r"\b(yaml\.safe_load|html/template|autoescape)\b",
        r"\b(path\.normalize|Path\.GetFullPath|realpath|basename)\b",
        r"\b(whitelist|allowlist|sanitize|escape|validate|validator)\b",
        r"\b(auth|authorize|permission|acl|role)\b",
        r"\b(subprocess\.(run|Popen)\s*\(\s*\[|exec\.Command\s*\(\s*[^\"']+\s*,)\b",
    ],
    "validation_signals": [
        r"\b(validate|sanitize|escape|check|verify|guard|filter)\b",
        r"\b(auth|authorize|permission|acl|role|requiredLogin|requiredAuth)\b",
        r"\b(is_safe|safe_path|normalized|canonical)\b",
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


def extract_security_hints(node_data) -> dict:
    text_parts = [
        str(node_data.get("source_name", "")),
        str(node_data.get("target_name", "")),
        str(node_data.get("desc", "")),
        str(node_data.get("source_code", "")),
    ]
    corpus = "\n".join(part for part in text_parts if part)
    return {
        key: _collect_pattern_hits(corpus, patterns)
        for key, patterns in SECURITY_HINT_PATTERNS.items()
    }


def security_hint_score(node_data) -> int:
    hints = extract_security_hints(node_data)
    return (
        len(hints["input_sources"]) * 4
        + len(hints["dangerous_sinks"]) * 6
        + len(hints["validation_signals"]) * 2
        + len(hints["safety_signals"])
    )


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


def gen_text_from_path(graph, path):
    text_list = []
    for index, node in enumerate(path):
        text_list.append(_format_node(index, graph.nodes[node]))
    return "\n".join(text_list)


def get_local_subgraph_nodes(graph, center_node, max_depth=2, max_nodes=12):
    visited = {center_node}
    ordered_nodes = [center_node]
    queue = deque([(center_node, 0)])

    while queue and len(ordered_nodes) < max_nodes:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue

        neighbors = list(graph.predecessors(current)) + list(graph.successors(current))
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
    ordered_nodes = get_local_subgraph_nodes(
        graph,
        center_node,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    text_list = []
    for index, node in enumerate(ordered_nodes):
        text_list.append(_format_node(index, graph.nodes[node]))
    return "\n".join(text_list)
