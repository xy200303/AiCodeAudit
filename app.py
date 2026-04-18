import json
import os
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from matplotlib import font_manager

from audit.service import run_audit


st.set_page_config(
    page_title="AI Code Audit",
    page_icon=":mag:",
    layout="wide",
)


def get_chinese_font_family() -> str:
    candidates = [
        "Microsoft YaHei",
        "SimHei",
        "Noto Sans CJK SC",
        "Source Han Sans SC",
        "WenQuanYi Zen Hei",
        "Arial Unicode MS",
    ]
    available_fonts = {font.name for font in font_manager.fontManager.ttflist}
    for candidate in candidates:
        if candidate in available_fonts:
            return candidate
    return "sans-serif"


def ensure_workspace() -> Path:
    workspace = Path("output") / "streamlit_runs"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def save_uploaded_zip(uploaded_file, workspace: Path) -> Path:
    target = workspace / uploaded_file.name
    with target.open("wb") as f:
        f.write(uploaded_file.getbuffer())
    return target


def extract_zip(zip_path: Path, workspace: Path):
    extract_dir = workspace / f"{zip_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_dir)

    children = [item for item in extract_dir.iterdir() if item.name != "__MACOSX"]
    if len(children) == 1 and children[0].is_dir():
        return extract_dir, children[0]
    return extract_dir, extract_dir


def read_text_file(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def discover_results(workspace: Path):
    results = []
    for result_dir in sorted(workspace.glob("*_result"), key=lambda path: path.stat().st_mtime, reverse=True):
        graph_files = sorted(result_dir.glob("*.graphml"))
        report_files = sorted(result_dir.glob("*_审计结果.log"))
        if not graph_files:
            continue
        graph_path = graph_files[0]
        report_path = report_files[0] if report_files else None
        project_hash = graph_path.stem
        results.append({
            "label": f"{result_dir.name} | {datetime.fromtimestamp(result_dir.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}",
            "project_hash": project_hash,
            "graph_path": str(graph_path),
            "report_path": str(report_path) if report_path else "",
            "output_dir": str(result_dir),
        })
    return results


def parse_report(report_text: str):
    sections = [section.strip() for section in report_text.split("--------------------------------") if section.strip()]
    if not sections and report_text.strip():
        sections = [report_text.strip()]

    parsed = []
    for section in sections:
        structured = parse_structured_report_section(section)
        if structured:
            parsed.extend(structured)
            continue
        parsed.append(parse_legacy_report_section(section))
    return parsed


def is_pass_finding(finding: dict) -> bool:
    finding_type = (finding.get("type") or "").strip()
    return finding_type in {"审计通过", "结构化审计通过结果", "审核通过"}


def format_finding_title(vuln_type: str, verdict: str, level: str) -> str:
    parts = [part for part in [vuln_type, verdict, level] if part]
    if not parts:
        return "未命名风险"
    if len(parts) == 1:
        return parts[0]
    return f"{parts[0]}（{' / '.join(parts[1:])}）"


def has_non_pass_findings(section: dict) -> bool:
    return any(not is_pass_finding(finding) for finding in section.get("findings", []))


def extract_tag_content(text: str, tag: str) -> str:
    match = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", text, re.DOTALL)
    return match.group(1).strip() if match else ""


def extract_line_value(text: str, field_name: str) -> str:
    match = re.search(rf"^{re.escape(field_name)}\s*:\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def parse_structured_report_section(section: str):
    if "<审计报告>" not in section:
        return []

    files = re.findall(r"<文件>\s*(.*?)\s*</文件>", section, re.DOTALL)
    parsed = []

    for file_block in files:
        file_path = extract_line_value(file_block, "路径") or "未知文件"
        conclusion = extract_line_value(file_block, "结论")
        findings = []

        for vuln_block in re.findall(r"<漏洞>\s*(.*?)\s*</漏洞>", file_block, re.DOTALL):
            vuln_type = extract_line_value(vuln_block, "类型")
            verdict = extract_line_value(vuln_block, "判定")
            level = extract_line_value(vuln_block, "等级")
            location = extract_line_value(vuln_block, "位置")
            findings.append({
                "type": format_finding_title(vuln_type, verdict, level),
                "location": location or "-",
                "feature": extract_tag_content(vuln_block, "代码特征"),
                "vector": extract_tag_content(vuln_block, "攻击向量"),
                "impact": extract_tag_content(vuln_block, "潜在影响"),
                "fix": extract_tag_content(vuln_block, "修复建议"),
            })

        if conclusion in {"审计通过", "结构化审计通过结果", "审核通过"} and not findings:
            findings.append({
                "type": "审计通过",
                "location": "-",
                "feature": "当前文件在本次上下文中未识别到明确漏洞",
                "vector": "",
                "impact": "",
                "fix": "",
            })

        parsed.append({
            "file_path": file_path,
            "findings": findings,
            "raw": section,
        })

    if parsed:
        return parsed

    if "<结论>审计通过</结论>" in section:
        return [{
            "file_path": "当前审计上下文",
            "findings": [{
                "type": "审计通过",
                "location": "-",
                "feature": "当前上下文未识别到明确漏洞",
                "vector": "",
                "impact": "",
                "fix": "",
            }],
            "raw": section,
        }]

    return []


def parse_legacy_report_section(section: str):
    lines = [line.rstrip("\n") for line in section.splitlines() if line.strip()]
    file_path = "未知文件"
    findings = []
    current = None
    current_field = None

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("// "):
            file_path = stripped[3:].strip()
        elif stripped.startswith("// 文件路径:"):
            file_path = stripped.replace("// 文件路径:", "", 1).strip()
        elif stripped.startswith("// 文件路径："):
            file_path = stripped.replace("// 文件路径：", "", 1).strip()
        elif stripped.startswith("■ 漏洞类型："):
            if current:
                findings.append(current)
            current = {
                "type": stripped.replace("■ 漏洞类型：", "", 1).strip(),
                "location": "",
                "feature": "",
                "vector": "",
                "impact": "",
                "fix": "",
            }
            current_field = None
        elif current and stripped.startswith("▶ 位置："):
            current["location"] = stripped.replace("▶ 位置：", "", 1).strip()
            current_field = "location"
        elif current and stripped.startswith("▶ 代码特征："):
            current["feature"] = stripped.replace("▶ 代码特征：", "", 1).strip()
            current_field = "feature"
        elif current and stripped.startswith("▶ 攻击向量："):
            current["vector"] = stripped.replace("▶ 攻击向量：", "", 1).strip()
            current_field = "vector"
        elif current and stripped.startswith("▶ 潜在影响："):
            current["impact"] = stripped.replace("▶ 潜在影响：", "", 1).strip()
            current_field = "impact"
        elif current and stripped.startswith("▶ 修复建议："):
            current["fix"] = stripped.replace("▶ 修复建议：", "", 1).strip()
            current_field = "fix"
        elif current and not stripped.startswith("<") and current_field:
            existing = current.get(current_field, "")
            if current_field == "feature":
                current[current_field] = (existing + "\n" + line.strip()) if existing else line.strip()
            else:
                current[current_field] = (existing + " " + stripped).strip() if existing else stripped

    if current:
        findings.append(current)

    if ("<审计通过>" in section or "<结论>审计通过</结论>" in section) and not findings:
        findings.append({
            "type": "审计通过",
            "location": "-",
            "feature": "当前上下文未识别到明确漏洞",
            "vector": "",
            "impact": "",
            "fix": "",
        })

    return {
        "file_path": file_path,
        "findings": findings,
        "raw": section,
    }


def build_graph_html(graph_path: str) -> str:
    graph = nx.read_graphml(graph_path)
    nodes = []
    edges = []

    for node_id, attrs in graph.nodes(data=True):
        label = attrs.get("source_name") or str(node_id)
        title = (
            f"文件: {attrs.get('name', '')}<br>"
            f"路径: {attrs.get('path', '')}<br>"
            f"描述: {attrs.get('desc', '')}<br>"
            f"行号: {attrs.get('start_code_line', '')}-{attrs.get('end_code_line', '')}"
        )
        nodes.append({
            "id": str(node_id),
            "label": label,
            "title": title,
            "group": attrs.get("name", "default"),
            "shape": "dot",
            "size": 14 if attrs.get("source_code") else 8,
        })

    for source, target in graph.edges():
        edges.append({
            "from": str(source),
            "to": str(target),
            "arrows": "to",
        })

    return f"""
    <div id="graph-status" style="padding:8px 12px;color:#475569;font-family:Microsoft YaHei;">图谱加载中...</div>
    <div id="graph" style="width:100%;height:760px;border-radius:18px;border:1px solid #e6e8ef;background:linear-gradient(180deg,#fbfbfd 0%,#f4f6fb 100%);"></div>
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/dist/vis-network.min.css"/>
    <script>
      const status = document.getElementById("graph-status");
      const renderGraph = () => {{
        if (typeof vis === "undefined") {{
          status.innerText = "图谱脚本加载失败，页面已回退到下方列表视图。";
          return;
        }}
        const nodes = new vis.DataSet({json.dumps(nodes, ensure_ascii=False)});
        const edges = new vis.DataSet({json.dumps(edges, ensure_ascii=False)});
        const container = document.getElementById("graph");
        const data = {{ nodes, edges }};
        const options = {{
          autoResize: true,
          interaction: {{
            hover: true,
            navigationButtons: true,
            keyboard: true
          }},
          physics: {{
            enabled: true,
            solver: "forceAtlas2Based",
            stabilization: {{ iterations: 300 }}
          }},
          layout: {{
            improvedLayout: true
          }},
          nodes: {{
            borderWidth: 1,
            borderWidthSelected: 2,
            color: {{
              background: "#ff8a65",
              border: "#d85d3c",
              highlight: {{ background: "#ff7043", border: "#b94722" }}
            }},
            font: {{
              color: "#1f2a44",
              size: 14,
              face: "Microsoft YaHei"
            }}
          }},
          edges: {{
            color: {{ color: "#94a3b8", highlight: "#f97316" }},
            smooth: {{ type: "dynamic" }}
          }},
          groups: {{
            default: {{ color: {{ background: "#ff8a65", border: "#d85d3c" }} }}
          }}
        }};
        const network = new vis.Network(container, data, options);
        network.once("stabilizationIterationsDone", function () {{
          network.fit({{ animation: true }});
          status.innerText = "图谱加载完成，可拖拽、缩放和悬停查看详情。";
        }});
      }};
      window.addEventListener("load", renderGraph);
      setTimeout(renderGraph, 400);
    </script>
    """


def render_graph_fallback(graph: nx.DiGraph):
    font_family = get_chinese_font_family()
    plt.rcParams["font.sans-serif"] = [font_family]
    plt.rcParams["axes.unicode_minus"] = False
    sample_nodes = list(graph.nodes())[:120]
    subgraph = graph.subgraph(sample_nodes).copy()
    fig, ax = plt.subplots(figsize=(14, 9))
    pos = nx.spring_layout(subgraph, seed=42, k=0.9)
    nx.draw_networkx(
        subgraph,
        pos=pos,
        ax=ax,
        with_labels=False,
        node_size=70,
        width=0.6,
        arrows=False,
        node_color="#ff8a65",
        edge_color="#94a3b8",
    )
    ax.set_title("依赖图谱静态预览（前120个节点）", fontsize=14, fontfamily=font_family)
    ax.axis("off")
    st.pyplot(fig, clear_figure=True)


def build_node_dataframe(graph: nx.DiGraph):
    rows = []
    for node_id, attrs in graph.nodes(data=True):
        rows.append({
            "节点ID": str(node_id),
            "文件": attrs.get("name", ""),
            "路径": attrs.get("path", ""),
            "代码单元": attrs.get("source_name", ""),
            "被调用目标": attrs.get("target_name", ""),
            "开始行": attrs.get("start_code_line", ""),
            "结束行": attrs.get("end_code_line", ""),
            "摘要": attrs.get("desc", ""),
        })
    return pd.DataFrame(rows)


def build_edge_dataframe(graph: nx.DiGraph):
    rows = []
    for source, target in graph.edges():
        rows.append({
            "源节点": str(source),
            "目标节点": str(target),
        })
    return pd.DataFrame(rows)


def render_analysis_page(workspace: Path):
    st.title("分析")
    st.caption("上传项目压缩包后，自动完成源码扫描、依赖分析与安全审计。")

    uploaded_file = st.file_uploader("上传项目压缩包", type=["zip"])
    if uploaded_file is None:
        st.info("请上传一个 zip 压缩包。")
        return

    if st.button("开始分析", type="primary", use_container_width=True):
        zip_path = save_uploaded_zip(uploaded_file, workspace)

        try:
            with st.status("正在解压并分析项目...", expanded=True) as status:
                st.write("保存上传文件")
                run_root, project_dir = extract_zip(zip_path, workspace)
                st.write(f"解压完成: `{project_dir}`")

                output_dir = workspace / f"{project_dir.name}_result"
                st.write("开始执行 AI 审计")
                result = run_audit(str(project_dir), str(output_dir), batch_size=st.session_state.batch_size)
                st.session_state.latest_result = result
                status.update(label="分析完成", state="complete")

            st.success("分析完成，请从侧边栏进入“结果可视化”或“依赖可视化”查看。")
        except zipfile.BadZipFile:
            st.error("上传文件不是有效的 zip 压缩包。")
        except Exception as exc:
            st.exception(exc)
        finally:
            if not st.session_state.keep_files:
                if zip_path.exists():
                    zip_path.unlink()
                if "run_root" in locals() and run_root.exists():
                    shutil.rmtree(run_root, ignore_errors=True)
                if "output_dir" in locals() and output_dir.exists():
                    shutil.rmtree(output_dir, ignore_errors=True)


def get_selected_result(workspace: Path):
    results = discover_results(workspace)
    latest = st.session_state.get("latest_result")
    if latest and all(item.get("project_hash") != latest.get("project_hash") for item in results):
        results.insert(0, {
            "label": f"{Path(latest['output_dir']).name} | 当前会话",
            **latest,
        })
    return results


def render_result_list_page(workspace: Path):
    st.title("结果可视化")
    results = get_selected_result(workspace)
    if not results:
        st.info("还没有可展示的结果，请先在“分析”页面执行一次审计。")
        return

    result_map = {item["label"]: item for item in results}
    selected_label = st.selectbox("选择一个分析结果", list(result_map.keys()))
    selected = result_map[selected_label]

    col1, col2, col3 = st.columns(3)
    col1.metric("项目哈希", selected["project_hash"][:12])
    col2.metric("GraphML", os.path.basename(selected["graph_path"]))
    col3.metric("报告日志", os.path.basename(selected["report_path"]) if selected["report_path"] else "未生成")

    if not selected["report_path"] or not os.path.exists(selected["report_path"]):
        st.warning("当前结果没有可用的审计日志。")
        return

    report_text = read_text_file(selected["report_path"])
    parsed_sections = parse_report(report_text)
    show_passed = st.toggle("显示审计通过结果", value=False, help="默认隐藏仅包含“审计通过”的审计块")
    show_raw_blocks = st.toggle("显示原始审计块", value=False, help="关闭可减少大量结果时的页面卡顿")

    if not parsed_sections:
        st.text_area("原始报告", report_text, height=400)
        return

    visible_sections = parsed_sections if show_passed else [section for section in parsed_sections if has_non_pass_findings(section)]

    total_findings = sum(len(section["findings"]) for section in parsed_sections)
    visible_findings = sum(
        len(section["findings"]) if show_passed else sum(1 for finding in section["findings"] if not is_pass_finding(finding))
        for section in parsed_sections
    )

    st.caption(f"当前展示 {len(visible_sections)} 个审计块，{visible_findings} 条结果；原始报告共 {len(parsed_sections)} 个审计块，{total_findings} 条结果。")

    if not visible_sections:
        st.info("当前结果中仅包含“审计通过”内容，已按设置隐藏。打开“显示审计通过结果”可查看完整输出。")
        return

    for section in visible_sections:
        st.markdown(f"### {section['file_path']}")
        if not section["findings"]:
            st.code(section["raw"], language="text")
            continue

        for finding in section["findings"]:
            if not show_passed and is_pass_finding(finding):
                continue
            with st.container(border=True):
                st.markdown(f"**漏洞类型**: {finding['type']}")
                st.markdown(f"**位置**: {finding['location'] or '-'}")
                if finding["feature"]:
                    st.markdown("**代码特征**:")
                    st.code(finding["feature"], language="text")
                else:
                    st.markdown("**代码特征**: -")
                if finding["vector"]:
                    st.markdown(f"**攻击向量**: {finding['vector']}")
                if finding["impact"]:
                    st.markdown(f"**潜在影响**: {finding['impact']}")
                if finding["fix"]:
                    st.markdown(f"**修复建议**: {finding['fix']}")
        if show_raw_blocks:
            raw_preview = section["raw"]
            if len(raw_preview) > 4000:
                raw_preview = raw_preview[:4000] + "\n\n...（原始审计块过长，已截断显示）"
            with st.expander("查看本文件原始审计块"):
                st.code(raw_preview, language="text")


def render_graph_page(workspace: Path):
    st.title("依赖可视化")
    results = get_selected_result(workspace)
    if not results:
        st.info("还没有可展示的图谱，请先在“分析”页面执行一次审计。")
        return

    result_map = {item["label"]: item for item in results}
    selected_label = st.selectbox("选择一个图谱结果", list(result_map.keys()), key="graph_select")
    selected = result_map[selected_label]

    if not os.path.exists(selected["graph_path"]):
        st.warning("当前结果没有可用的 graphml 文件。")
        return

    graph = nx.read_graphml(selected["graph_path"])
    col1, col2, col3 = st.columns(3)
    col1.metric("节点数", graph.number_of_nodes())
    col2.metric("边数", graph.number_of_edges())
    col3.metric("结果目录", Path(selected["output_dir"]).name)

    graph_tab, static_tab, node_tab, edge_tab = st.tabs(["交互图谱", "静态预览", "节点列表", "边列表"])

    with graph_tab:
        components.html(build_graph_html(selected["graph_path"]), height=820, scrolling=False)

    with static_tab:
        render_graph_fallback(graph)

    with node_tab:
        node_df = build_node_dataframe(graph)
        search_text = st.text_input("搜索节点 / 文件 / 路径", key="node_search").strip().lower()
        if search_text:
            node_df = node_df[
                node_df.astype(str).apply(lambda col: col.str.lower().str.contains(search_text, na=False))
                .any(axis=1)
            ]
        st.dataframe(node_df, use_container_width=True, height=520)

    with edge_tab:
        edge_df = build_edge_dataframe(graph)
        st.dataframe(edge_df, use_container_width=True, height=520)


def init_session_state():
    st.session_state.setdefault("batch_size", 10)
    st.session_state.setdefault("keep_files", True)
    st.session_state.setdefault("latest_result", None)


def main():
    workspace = ensure_workspace()
    init_session_state()

    with st.sidebar:
        st.markdown("## 运行参数")
        st.session_state.batch_size = st.slider("每批任务数", min_value=1, max_value=30, value=st.session_state.batch_size)
        st.session_state.keep_files = st.checkbox("保留上传与解压文件", value=st.session_state.keep_files)
        st.markdown("---")
        page = st.radio("功能导航", ["分析", "结果可视化", "依赖可视化"], label_visibility="collapsed")

    if page == "分析":
        render_analysis_page(workspace)
    elif page == "结果可视化":
        render_result_list_page(workspace)
    else:
        render_graph_page(workspace)


if __name__ == "__main__":
    main()
