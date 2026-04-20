import os
from collections import deque

from audit.chunker import split_source_file_semantic
from loguru import logger

from audit.tree_sitter_parser import supports_tree_sitter
from config import C
from models import SourceDir, SourceFile


def scan_project_struct(project_dir):
    abs_path = os.path.abspath(project_dir)
    dir_name = os.path.basename(abs_path)
    root_dir = SourceDir(path=abs_path, name=dir_name)
    scan_dir(abs_path, root_dir)
    return root_dir


def scan_dir(dir_path, parent_dir):
    try:
        entries = os.scandir(dir_path)
    except OSError as e:
        print(f"Failed to read directory {dir_path}: {e}")
        return

    for entry in entries:
        entry_path = os.path.join(dir_path, entry.name)
        if is_excluded_dir(entry_path):
            continue
        if entry.is_dir():
            sub_dir = SourceDir(path=entry_path, name=entry.name)
            scan_dir(entry_path, sub_dir)
            parent_dir.source_dirs.append(sub_dir)
            continue

        ext = os.path.splitext(entry.name)[1]
        if not (is_source_file(ext) or is_config_file(ext)):
            continue

        file_info = entry.stat()
        if file_info.st_size / (1024 * 1024) > C.project.exclude_max_file_size:
            continue

        content = read_source_file(entry_path)
        if content is None:
            continue

        parent_dir.source_files.append(SourceFile(
            path=entry_path,
            name=entry.name,
            source_code=content,
            extension=ext
        ))


def is_source_file(ext):
    return ext in C.project.source_file_ext


def is_config_file(ext):
    return ext in C.project.config_file_ext


def is_excluded_dir(dir_path):
    normalized_parts = set(os.path.normpath(dir_path).split(os.sep))
    return any(exclude in normalized_parts for exclude in C.project.exclude_dir)


def read_source_file(file_path):
    encodings = ("utf-8", "utf-8-sig", "gb18030", "latin-1")
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except Exception as e:
            logger.warning("读取文件失败: {} | {}", file_path, e)
            return None

    logger.warning("文件编码无法识别，已跳过: {}", file_path)
    return None


def _should_keep_whole_file(file: SourceFile) -> bool:
    parse_engine = getattr(C.project, "dependency_parse_engine", "auto").lower()
    if parse_engine == "llm":
        return False
    return supports_tree_sitter(file.extension)


def build_tree_string(dir_obj, last=False, tree=None):
    if tree is None:
        tree = []

    indent = ""
    for i, is_last in enumerate(tree):
        if i < len(tree) - 1:
            indent += "   " if is_last else "│  "
        else:
            indent += "└─ " if last else "├─ "

    result = f"{indent}{dir_obj.name}\n"

    for i, file in enumerate(dir_obj.source_files):
        is_last_file = i == len(dir_obj.source_files) - 1 and len(dir_obj.source_dirs) == 0
        file_indent = indent + ("└─ " if is_last_file else "├─ ")
        result += f"{file_indent}{file.name} ({file.extension})\n"

    for i, sub_dir in enumerate(dir_obj.source_dirs):
        new_tree = tree + [i == len(dir_obj.source_dirs) - 1]
        result += build_tree_string(sub_dir, i == len(dir_obj.source_dirs) - 1, new_tree)

    return result


def print_source_dir(dir_obj):
    return build_tree_string(dir_obj, True, [])


def traverse_source_dir_bfs(root):
    text = []
    queue = deque([root])

    while queue:
        current = queue.popleft()
        for file in current.source_files:
            file_info = f"<代码单元>\n//{file.path}\n{file.source_code}<代码单元>"
            text.append(file_info)
        for sub_dir in current.source_dirs:
            queue.append(sub_dir)
    return text


def get_all_source_files_bfs(root_dir, chunk_token_size):
    """
    使用广度优先搜索获取 SourceDir 对象中的所有 SourceFile，并按 token 分块。
    """
    def split_large_files(files):
        new_files = []
        for file in files:
            if _should_keep_whole_file(file):
                new_files.append(file)
                continue
            new_files.extend(split_source_file_semantic(file, chunk_token_size))
        return new_files

    queue = deque([root_dir])
    all_files = []
    while queue:
        current_dir = queue.popleft()
        all_files.extend(split_large_files(current_dir.source_files))
        queue.extend(current_dir.source_dirs)
    return all_files
