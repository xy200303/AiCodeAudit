import hashlib
import re
import sys
from typing import List

import networkx as nx
import tiktoken
from loguru import logger
from matplotlib import pyplot as plt

from config import C
from models import CodeUnit


def is_cmd_mode():
    """
    尝试判断脚本是否从命令行运行。
    这种方法并不是100%可靠，但对于大多数情况应该足够。
    """
    if len(sys.argv) > 1:
        return True
    if hasattr(sys, 'ps1'):
        return False
    if 'idlelib.run' in sys.modules:
        return False
    return True


def get_encoding():
    try:
        return tiktoken.encoding_for_model(C.openai.model)
    except KeyError:
        logger.warning("未找到模型 {} 对应的 tokenizer，回退到 cl100k_base", C.openai.model)
        return tiktoken.get_encoding("cl100k_base")


def count_text_tokens(text: str) -> int:
    return len(get_encoding().encode(text))


def count_message_tokens(messages: list) -> int:
    encoding = get_encoding()
    total_tokens = 0
    for message in messages:
        text = f"{message['role']}: {message['content']}"
        total_tokens += len(encoding.encode(text))
    return total_tokens


def gen_line_code(text: str, start_line: int = 1):
    """
    为输入的多行文本自动编制行号。

    :param text: 输入的多行文本字符串
    :return: 添加了行号的多行文本字符串
    """
    lines = text.splitlines()
    if not lines:
        return ""

    max_line_number_length = len(str(start_line + len(lines) - 1))
    result = []
    for line_number, line in enumerate(lines, start=start_line):
        formatted_line_number = str(line_number).rjust(max_line_number_length)
        result.append(f"{formatted_line_number}: {line}")

    return "\n".join(result)


def get_code_by_line(text: str, start_line: int, end_line: int, base_line: int = 1) -> str:
    """
    根据指定的起始行和结束行从多行文本中提取内容。
    """
    lines = text.splitlines()
    relative_start = start_line - base_line + 1
    relative_end = end_line - base_line + 1
    if relative_start < 1 or relative_end > len(lines) or relative_start > relative_end:
        logger.error("无效的起始行或结束行: {}-{} (base_line={})", start_line, end_line, base_line)
        return ""

    return "\n".join(lines[relative_start - 1:relative_end])


def normalize_llm_output(text: str) -> str:
    normalized = text.strip()
    normalized = normalized.replace("```text", "").replace("```plaintext", "").replace("```", "")
    return normalized.strip()


def extract_output_unit_content(input_text: str) -> str:
    normalized = normalize_llm_output(input_text)

    tagged_match = re.search(r'<输出单元>\s*(.*?)\s*<输出单元>', normalized, re.DOTALL)
    if tagged_match:
        return tagged_match.group(1).strip()

    if "<SEP>" in normalized:
        candidate_lines = []
        for line in normalized.splitlines():
            stripped = line.strip()
            if stripped.count("<SEP>") == 3:
                candidate_lines.append(stripped)
        if candidate_lines:
            return "\n".join(candidate_lines)

    raise ValueError("未找到 <输出单元> 标签或标签格式不正确")


def parse_code_unit_line(line: str, code: str, path: str, name: str, base_line: int) -> CodeUnit:
    parts = line.split('<SEP>')
    if len(parts) != 4:
        raise ValueError(f"行 '{line}' 的格式不正确，应包含四个部分")

    line_list = parts[3].strip().split("-")
    if len(line_list) != 2:
        raise ValueError(f"解析行号错误: {line}")

    start_code_line = int(line_list[0])
    end_code_line = int(line_list[1])
    return CodeUnit(
        source_name=parts[0].strip(),
        target_name=parts[1].strip(),
        source_desc=parts[2].strip(),
        start_code_line=start_code_line,
        end_code_line=end_code_line,
        source_code=get_code_by_line(
            code,
            start_line=start_code_line,
            end_line=end_code_line,
            base_line=base_line,
        ),
        path=path,
        name=name
    )


def parse_code_uint(code: str, path: str, name: str, input_text: str, base_line: int = 1):
    """
    从输入文本中提取并解析 <输出单元> 标签内的内容。
    """
    normalized = normalize_llm_output(input_text)
    if normalized.replace("\n", "").strip().find("未发现数据") != -1:
        return None

    content = extract_output_unit_content(normalized)
    if not content:
        return None

    parsed_data = []
    for line in content.strip().split('\n'):
        stripped = line.strip()
        if not stripped or "<SEP>" not in stripped:
            continue
        parsed_data.append(parse_code_unit_line(stripped, code, path, name, base_line))

    return parsed_data or None


def gen_graph_by_codeunits(codeunits: List[CodeUnit]):
    """
    根据 CodeUnitList 生成知识图谱。
    """
    graph = nx.DiGraph()
    for unit in codeunits:
        source_name = f"{unit.path}|{unit.source_name}"
        target_name = f"{unit.path}|{unit.target_name}"
        source_data = {
            "source_code": unit.source_code,
            "target_name": unit.target_name,
            "source_name": unit.source_name,
            "desc": unit.source_desc,
            "start_code_line": unit.start_code_line,
            "end_code_line": unit.end_code_line,
            "name": unit.name,
            "path": unit.path,
        }
        if graph.has_node(source_name):
            graph.nodes[source_name].update(source_data)
        else:
            graph.add_node(source_name, **source_data)

        if not graph.has_node(target_name):
            graph.add_node(
                target_name,
                source_code="",
                source_name=unit.target_name,
                target_name="",
                desc="",
                start_code_line=0,
                end_code_line=0,
                name=unit.name,
                path=unit.path,
            )
        graph.add_edge(source_name, target_name)
    return graph


def visualize_graph(graph, layout=nx.spring_layout, node_size=700, node_color="lightblue", font_size=10, arrowsize=20):
    """
    使用 Matplotlib 可视化知识图谱，并允许选择不同的布局方法。
    """
    pos = layout(graph)
    node_labels = {node: node for node in graph.nodes()}
    nx.draw_networkx_nodes(graph, pos, node_size=node_size, node_color=node_color)
    nx.draw_networkx_labels(graph, pos, labels=node_labels, font_size=font_size, font_family="sans-serif")
    nx.draw_networkx_edges(graph, pos, edgelist=graph.edges(), arrowstyle='->', arrowsize=arrowsize)
    plt.show()


def calculate_md5(text):
    hash_object = hashlib.md5()
    hash_object.update(text.encode())
    return hash_object.hexdigest()


def write_file(file, text):
    with open(file, "w", encoding="utf-8") as f:
        f.write(text)
