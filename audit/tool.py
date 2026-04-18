from collections import deque


def _format_node(index, node_data):
    return f"""<路径_{index}>
        源码路径:{node_data.get("path")}
        源码文件名称:{node_data.get("name")}
        调用代码单元名称:{node_data.get("source_name")}
        被调用代码单元名称:{node_data.get("target_name")}
        当前代码源码:{node_data.get("source_code")}
        源码摘要描述:{node_data.get("desc")}
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
