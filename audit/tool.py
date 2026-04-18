from collections import deque
import os
import re


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
