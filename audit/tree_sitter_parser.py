from __future__ import annotations

import os
import re
from dataclasses import dataclass

from audit.chunker import split_source_file_semantic
from loguru import logger

from models import CodeUnit, SourceFile
from utils import count_text_tokens, get_code_by_line

try:
    from tree_sitter import Node  # type: ignore
    from tree_sitter_languages import get_parser  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    Node = None
    get_parser = None


_TREE_SITTER_RUNTIME_OK = None


TREE_SITTER_LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "c_sharp",
}

CLASS_NODE_TYPES = {
    "class_definition",
    "class_declaration",
}

FUNCTION_NODE_TYPES = {
    "function_definition",
    "function_declaration",
    "method_definition",
    "method_declaration",
    "constructor_declaration",
}

CALL_NODE_TYPES = {
    "call",
    "call_expression",
    "invocation_expression",
    "method_invocation",
    "new_expression",
    "object_creation_expression",
}

IMPORT_NODE_TYPES = {
    "import_statement",
    "import_from_statement",
    "import_declaration",
    "import_spec",
    "require_call",
    "package_clause",
    "package_declaration",
    "using_directive",
    "using_declaration",
    "namespace_use_declaration",
    "namespace_definition",
    "preproc_include",
}

DECORATED_NODE_TYPES = {
    "decorated_definition",
}

IDENTIFIER_NODE_TYPES = {
    "identifier",
    "field_identifier",
    "property_identifier",
    "type_identifier",
    "qualified_identifier",
    "scoped_identifier",
    "namespace_identifier",
    "dotted_name",
}

MEMBER_NODE_TYPES = {
    "attribute",
    "field_expression",
    "member_expression",
    "qualified_identifier",
    "scoped_identifier",
}


@dataclass
class ScopeInfo:
    name: str
    start_line: int
    end_line: int


def is_tree_sitter_available() -> bool:
    global _TREE_SITTER_RUNTIME_OK
    if get_parser is None:
        return False
    if _TREE_SITTER_RUNTIME_OK is not None:
        return _TREE_SITTER_RUNTIME_OK

    try:
        get_parser("python")
        _TREE_SITTER_RUNTIME_OK = True
    except Exception as exc:  # pragma: no cover - runtime environment dependent
        logger.warning(
            "Tree-sitter 运行时不可用，已自动禁用并回退到 LLM。常见原因是 tree-sitter 与 tree-sitter-languages 版本不兼容: {}",
            exc,
        )
        _TREE_SITTER_RUNTIME_OK = False
    return _TREE_SITTER_RUNTIME_OK


def supports_tree_sitter(extension: str) -> bool:
    return extension.lower() in TREE_SITTER_LANGUAGE_BY_EXTENSION and is_tree_sitter_available()


def get_tree_sitter_language(extension: str) -> str | None:
    return TREE_SITTER_LANGUAGE_BY_EXTENSION.get(extension.lower())


def _module_scope_name(source_file: SourceFile) -> str:
    return os.path.splitext(source_file.name)[0]


def _scope_name(class_stack: list[str], func_name: str) -> str:
    if class_stack:
        return f"{class_stack[-1]}.{func_name}"
    return func_name


def _node_text(node: Node | None, source_bytes: bytes) -> str:
    if node is None:
        return ""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore").strip()


def _first_named_child_by_types(node: Node, node_types: set[str]):
    for child in node.named_children:
        if child.type in node_types:
            return child
    return None


def _find_first_descendant(node: Node, node_types: set[str]):
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in node_types:
            return current
        stack.extend(reversed(current.named_children))
    return None


def _extract_import_targets(raw: str, extension: str) -> list[str]:
    normalized = " ".join(raw.split())
    targets: list[str] = []

    if extension == ".py":
        if normalized.startswith("import "):
            for item in normalized.replace("import ", "", 1).split(","):
                name = item.strip().split(" as ")[0].strip()
                if name:
                    targets.append(f"import:{name}")
        elif normalized.startswith("from ") and " import " in normalized:
            module_part, imported_part = normalized.split(" import ", 1)
            module = module_part.replace("from ", "", 1).strip()
            imported_part = imported_part.strip().strip("()")
            for item in imported_part.split(","):
                name = item.strip().split(" as ")[0].strip()
                if name:
                    targets.append(f"import:{module}.{name}".strip("."))
        return targets

    if extension in {".js", ".ts"}:
        import_matches = re.findall(r'import\s+(?:.+?\s+from\s+)?["\']([^"\']+)["\']', normalized)
        require_matches = re.findall(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)', normalized)
        for name in import_matches + require_matches:
            targets.append(f"import:{name}")
        return list(dict.fromkeys(targets))

    if extension == ".java":
        for match in re.findall(r'import\s+(?:static\s+)?([a-zA-Z0-9_.*]+)\s*;', normalized):
            targets.append(f"import:{match}")
        return targets

    if extension == ".go":
        if normalized.startswith("package "):
            package_name = normalized.replace("package ", "", 1).strip()
            return [f"import:{package_name}"] if package_name else []
        for match in re.findall(r'"([^"]+)"', normalized):
            targets.append(f"import:{match}")
        return targets

    if extension == ".php":
        for match in re.findall(r'(?:include|include_once|require|require_once)\s*\(?\s*[\'"]([^\'"]+)[\'"]', normalized):
            targets.append(f"import:{match}")
        for match in re.findall(r'use\s+([a-zA-Z0-9_\\]+)', normalized):
            targets.append(f"import:{match}")
        return list(dict.fromkeys(targets))

    if extension in {".c", ".cpp"}:
        for match in re.findall(r'#include\s*[<"]([^>"]+)[>"]', normalized):
            targets.append(f"import:{match}")
        return targets

    if extension == ".cs":
        for match in re.findall(r'using\s+([a-zA-Z0-9_.]+)\s*;', normalized):
            targets.append(f"import:{match}")
        return targets

    return targets


def _extract_expression_name(node: Node | None, source_bytes: bytes) -> str:
    if node is None:
        return ""

    if node.type in IDENTIFIER_NODE_TYPES:
        return _node_text(node, source_bytes)

    if node.type in MEMBER_NODE_TYPES:
        left = ""
        right = ""
        for field_name in ("object", "argument", "receiver", "operand", "left", "scope", "qualifier"):
            candidate = node.child_by_field_name(field_name)
            if candidate is not None:
                left = _extract_expression_name(candidate, source_bytes)
                if left:
                    break
        for field_name in ("attribute", "name", "field", "member", "right"):
            candidate = node.child_by_field_name(field_name)
            if candidate is not None:
                right = _extract_expression_name(candidate, source_bytes)
                if right:
                    break

        named_children = node.named_children
        if not left and named_children:
            left = _extract_expression_name(named_children[0], source_bytes)
        if not right and len(named_children) > 1:
            right = _extract_expression_name(named_children[-1], source_bytes)
        return f"{left}.{right}".strip(".")

    if node.type in CALL_NODE_TYPES:
        return _extract_callable_name(node, source_bytes)

    if node.type == "subscript_expression" or node.type == "subscript":
        value_node = node.child_by_field_name("value") or _first_named_child_by_types(node, IDENTIFIER_NODE_TYPES | MEMBER_NODE_TYPES)
        return _extract_expression_name(value_node, source_bytes)

    if node.named_children:
        for child in node.named_children:
            candidate = _extract_expression_name(child, source_bytes)
            if candidate:
                return candidate

    return _node_text(node, source_bytes)


def _extract_callable_name(node: Node, source_bytes: bytes) -> str:
    for field_name in ("function", "name", "constructor", "object", "type"):
        candidate = node.child_by_field_name(field_name)
        if candidate is not None:
            name = _extract_expression_name(candidate, source_bytes)
            if name:
                return name

    for child in node.named_children:
        candidate = _extract_expression_name(child, source_bytes)
        if candidate:
            return candidate
    return ""


def _build_desc(target_name: str) -> str:
    if target_name == "无外部依赖":
        return "未发现外部依赖"
    if target_name.startswith("import:"):
        return f"导入{target_name.split(':', 1)[1][:12]}"
    return f"调用{target_name[:14]}" if target_name else "显式依赖"


class GenericTreeSitterDependencyVisitor:
    def __init__(self, source_file: SourceFile):
        self.source_file = source_file
        self.extension = source_file.extension.lower()
        self.base_line = source_file.start_line
        self.source_bytes = source_file.source_code.encode("utf-8")
        self.class_stack: list[str] = []
        module_scope = ScopeInfo(
            _module_scope_name(source_file),
            self.base_line,
            self.base_line + max(0, len(source_file.source_code.splitlines()) - 1),
        )
        self.scope_stack: list[ScopeInfo] = [module_scope]
        self.scope_ranges: dict[str, tuple[int, int]] = {
            module_scope.name: (module_scope.start_line, module_scope.end_line)
        }
        self.scope_dependencies: dict[str, list[tuple[str, int, int]]] = {}

    def current_scope(self) -> ScopeInfo:
        return self.scope_stack[-1]

    def add_dependency(self, target_name: str):
        if not target_name:
            return
        scope = self.current_scope()
        deps = self.scope_dependencies.setdefault(scope.name, [])
        candidate = (target_name, scope.start_line, scope.end_line)
        if candidate not in deps:
            deps.append(candidate)

    def walk(self, node: Node):
        if node.type in DECORATED_NODE_TYPES:
            self._visit_decorated(node)
            return
        if node.type in CLASS_NODE_TYPES:
            self._visit_class(node)
            return
        if node.type in FUNCTION_NODE_TYPES:
            self._visit_function_like(node)
            return
        if node.type in IMPORT_NODE_TYPES:
            self._visit_import(node)
            return
        if node.type in CALL_NODE_TYPES:
            self._visit_call(node)
            return
        if self.extension in {".js", ".ts"} and node.type == "variable_declarator":
            self._visit_js_variable_declarator(node)
            return

        for child in node.named_children:
            self.walk(child)

    def _visit_decorated(self, node: Node):
        definition = _first_named_child_by_types(node, CLASS_NODE_TYPES | FUNCTION_NODE_TYPES)
        if definition is not None:
            self.walk(definition)

    def _visit_class(self, node: Node):
        name_node = node.child_by_field_name("name") or _find_first_descendant(node, IDENTIFIER_NODE_TYPES)
        class_name = _node_text(name_node, self.source_bytes) or "AnonymousClass"
        self.class_stack.append(class_name)
        body = node.child_by_field_name("body") or _first_named_child_by_types(node, {"block", "class_body", "declaration_list"})
        if body:
            for child in body.named_children:
                self.walk(child)
        self.class_stack.pop()

    def _visit_function_like(self, node: Node):
        name_node = node.child_by_field_name("name") or _find_first_descendant(node, IDENTIFIER_NODE_TYPES)
        func_name = _node_text(name_node, self.source_bytes) or "anonymous"
        start_line = self.base_line + node.start_point[0]
        end_line = self.base_line + node.end_point[0]
        scope = ScopeInfo(_scope_name(self.class_stack, func_name), start_line, end_line)
        self.scope_stack.append(scope)
        self.scope_ranges[scope.name] = (start_line, end_line)
        body = node.child_by_field_name("body") or _first_named_child_by_types(node, {"block", "statement_block", "function_body"})
        if body:
            for child in body.named_children:
                self.walk(child)
        else:
            for child in node.named_children:
                if child is not name_node:
                    self.walk(child)
        self.scope_stack.pop()
        self.scope_dependencies.setdefault(scope.name, [])

    def _visit_import(self, node: Node):
        raw = _node_text(node, self.source_bytes)
        for target in _extract_import_targets(raw, self.extension):
            self.add_dependency(target)

    def _visit_call(self, node: Node):
        target_name = _extract_callable_name(node, self.source_bytes)
        if target_name:
            self.add_dependency(target_name)
        for child in node.named_children:
            self.walk(child)

    def _visit_js_variable_declarator(self, node: Node):
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if value_node is not None and value_node.type in {"arrow_function", "function", "function_expression"}:
            func_name = _node_text(name_node, self.source_bytes) or "anonymous"
            start_line = self.base_line + node.start_point[0]
            end_line = self.base_line + node.end_point[0]
            scope = ScopeInfo(_scope_name(self.class_stack, func_name), start_line, end_line)
            self.scope_stack.append(scope)
            self.scope_ranges[scope.name] = (start_line, end_line)
            body = value_node.child_by_field_name("body") or _first_named_child_by_types(value_node, {"statement_block"})
            if body:
                for child in body.named_children:
                    self.walk(child)
            self.scope_stack.pop()
            self.scope_dependencies.setdefault(scope.name, [])
            return

        for child in node.named_children:
            self.walk(child)


def _build_code_units_from_visitor(source_file: SourceFile, visitor: GenericTreeSitterDependencyVisitor) -> list[CodeUnit] | None:
    code_units: list[CodeUnit] = []
    for scope_name, deps in visitor.scope_dependencies.items():
        start_line, end_line = visitor.scope_ranges.get(scope_name, (source_file.start_line, source_file.start_line))
        scoped_code = get_code_by_line(
            source_file.source_code,
            start_line=start_line,
            end_line=end_line,
            base_line=source_file.start_line,
        )

        if not deps:
            code_units.append(CodeUnit(
                source_code=scoped_code,
                start_code_line=start_line,
                end_code_line=end_line,
                name=source_file.name,
                path=source_file.path,
                source_name=scope_name,
                target_name="无外部依赖",
                source_desc="未发现外部依赖",
            ))
            continue

        for target_name, _, _ in deps:
            code_units.append(CodeUnit(
                source_code=scoped_code,
                start_code_line=start_line,
                end_code_line=end_line,
                name=source_file.name,
                path=source_file.path,
                source_name=scope_name,
                target_name=target_name,
                source_desc=_build_desc(target_name),
            ))
    return code_units or None


def _build_tree_from_source(source_file: SourceFile, language: str):
    try:
        parser = get_parser(language)
        return parser.parse(source_file.source_code.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - optional dependency runtime
        logger.warning("Tree-sitter 解析失败，回退其他方案: {} | {} | {}", language, source_file.path, exc)
        return None


def _fallback_tree_sitter_by_semantic_chunks(source_file: SourceFile, language: str) -> list[CodeUnit] | None:
    total_tokens = max(1, count_text_tokens(source_file.source_code))
    chunk_token_size = min(12000, max(2000, total_tokens // 2))
    fallback_chunks = split_source_file_semantic(source_file, chunk_token_size, isolate_boundaries=True)

    logger.warning(
        "Tree-sitter 整文件解析失败，尝试按较大语义块回退: {} | chunks={}",
        source_file.path,
        len(fallback_chunks),
    )

    all_code_units: list[CodeUnit] = []
    successful_chunks = 0
    for chunk in fallback_chunks:
        tree = _build_tree_from_source(chunk, language)
        if tree is None or tree.root_node is None or tree.root_node.has_error:
            continue
        visitor = GenericTreeSitterDependencyVisitor(chunk)
        visitor.walk(tree.root_node)
        chunk_units = _build_code_units_from_visitor(chunk, visitor)
        if chunk_units:
            all_code_units.extend(chunk_units)
            successful_chunks += 1

    if successful_chunks == 0:
        return None

    logger.warning(
        "Tree-sitter 语义块回退成功: {} | success_chunks={} | total_code_units={}",
        source_file.path,
        successful_chunks,
        len(all_code_units),
    )
    return all_code_units or None


def extract_code_units_with_tree_sitter(source_file: SourceFile) -> list[CodeUnit] | None:
    if not supports_tree_sitter(source_file.extension):
        return None

    language = get_tree_sitter_language(source_file.extension)
    if language is None:
        return None

    tree = _build_tree_from_source(source_file, language)
    if tree is None:
        return None

    if tree.root_node is None or tree.root_node.has_error:
        logger.warning("Tree-sitter 发现语法错误，尝试语义块回退: {}", source_file.path)
        return _fallback_tree_sitter_by_semantic_chunks(source_file, language)

    visitor = GenericTreeSitterDependencyVisitor(source_file)
    visitor.walk(tree.root_node)
    return _build_code_units_from_visitor(source_file, visitor)
