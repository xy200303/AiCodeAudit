import re

from models import SourceFile
from utils import get_encoding


SEMANTIC_BOUNDARY_PATTERNS = {
    ".py": [
        r"^\s*@",
        r"^\s*(async\s+def|def|class)\b",
    ],
    ".js": [
        r"^\s*(export\s+)?(async\s+)?function\b",
        r"^\s*(export\s+)?class\b",
        r"^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?\(",
        r"^\s*\w+\s*:\s*(async\s*)?\(",
    ],
    ".ts": [
        r"^\s*(export\s+)?(async\s+)?function\b",
        r"^\s*(export\s+)?class\b",
        r"^\s*(export\s+)?interface\b",
        r"^\s*(export\s+)?type\b",
        r"^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?\(",
    ],
    ".java": [
        r"^\s*(public|private|protected)?\s*(static\s+)?class\b",
        r"^\s*(public|private|protected)?\s*(static\s+)?[\w<>\[\],\s]+\s+\w+\s*\([^;]*\)\s*\{?\s*$",
    ],
    ".go": [
        r"^\s*func\b",
        r"^\s*type\s+\w+\s+struct\b",
        r"^\s*type\s+\w+\s+interface\b",
    ],
    ".php": [
        r"^\s*(abstract\s+|final\s+)?class\b",
        r"^\s*(public|private|protected)?\s*function\b",
    ],
    ".c": [
        r"^\s*(static\s+)?[\w\*\s]+\s+\w+\s*\([^;]*\)\s*\{?\s*$",
        r"^\s*(struct|typedef|enum)\b",
    ],
    ".cpp": [
        r"^\s*(template\s*<.*>\s*)?[\w:\<\>\*\&\s]+\s+\w+\s*\([^;]*\)\s*(const)?\s*\{?\s*$",
        r"^\s*(class|struct|namespace)\b",
    ],
    ".cs": [
        r"^\s*(public|private|protected|internal)?\s*(static\s+)?class\b",
        r"^\s*(public|private|protected|internal)?\s*(static\s+)?[\w<>\[\],\s]+\s+\w+\s*\([^;]*\)\s*\{?\s*$",
    ],
}


def _line_token_count(text: str) -> int:
    return len(get_encoding().encode(text))


def _matches_semantic_boundary(line: str, extension: str) -> bool:
    patterns = SEMANTIC_BOUNDARY_PATTERNS.get(extension.lower(), [])
    return any(re.match(pattern, line) for pattern in patterns)


def _find_semantic_boundaries(lines: list[str], extension: str) -> list[int]:
    boundaries = [1]
    for line_number, line in enumerate(lines, start=1):
        if line_number == 1:
            continue
        if _matches_semantic_boundary(line, extension):
            boundaries.append(line_number)
    return sorted(set(boundaries))


def _build_sections(lines: list[str], extension: str) -> list[tuple[int, list[str]]]:
    if not lines:
        return []

    boundaries = _find_semantic_boundaries(lines, extension)
    sections = []
    for index, start_line in enumerate(boundaries):
        end_line = boundaries[index + 1] - 1 if index + 1 < len(boundaries) else len(lines)
        sections.append((start_line, lines[start_line - 1:end_line]))
    return sections


def _split_section_by_lines(
    file: SourceFile,
    start_line: int,
    section_lines: list[str],
    chunk_token_size: int,
) -> list[SourceFile]:
    chunks = []
    current_lines = []
    current_tokens = 0
    chunk_start_line = start_line

    for offset, line in enumerate(section_lines):
        line_number = start_line + offset
        line_tokens = _line_token_count(line + "\n")
        if current_lines and current_tokens + line_tokens > chunk_token_size:
            chunks.append(SourceFile(
                path=file.path,
                name=file.name,
                source_code="\n".join(current_lines),
                extension=file.extension,
                start_line=chunk_start_line,
            ))
            current_lines = []
            current_tokens = 0
            chunk_start_line = line_number

        current_lines.append(line)
        current_tokens += line_tokens

    if current_lines:
        chunks.append(SourceFile(
            path=file.path,
            name=file.name,
            source_code="\n".join(current_lines),
            extension=file.extension,
            start_line=chunk_start_line,
        ))
    return chunks


def split_source_file_semantic(
    source_file: SourceFile,
    chunk_token_size: int,
    isolate_boundaries: bool = False,
) -> list[SourceFile]:
    lines = source_file.source_code.splitlines()
    if not lines:
        return [source_file]

    sections = _build_sections(lines, source_file.extension)
    if not sections:
        return [source_file]

    chunks = []
    current_lines = []
    current_tokens = 0
    current_start_line = source_file.start_line

    for relative_start_line, section_lines in sections:
        absolute_start_line = source_file.start_line + relative_start_line - 1
        section_text = "\n".join(section_lines)
        section_tokens = _line_token_count(section_text)

        if isolate_boundaries and section_tokens <= chunk_token_size:
            if current_lines:
                chunks.append(SourceFile(
                    path=source_file.path,
                    name=source_file.name,
                    source_code="\n".join(current_lines),
                    extension=source_file.extension,
                    start_line=current_start_line,
                ))
                current_lines = []
                current_tokens = 0
            chunks.append(SourceFile(
                path=source_file.path,
                name=source_file.name,
                source_code=section_text,
                extension=source_file.extension,
                start_line=absolute_start_line,
            ))
            current_start_line = absolute_start_line + len(section_lines)
            continue

        if section_tokens > chunk_token_size:
            if current_lines:
                chunks.append(SourceFile(
                    path=source_file.path,
                    name=source_file.name,
                    source_code="\n".join(current_lines),
                    extension=source_file.extension,
                    start_line=current_start_line,
                ))
                current_lines = []
                current_tokens = 0
            chunks.extend(_split_section_by_lines(source_file, absolute_start_line, section_lines, chunk_token_size))
            current_start_line = absolute_start_line + len(section_lines)
            continue

        if current_lines and current_tokens + section_tokens > chunk_token_size:
            chunks.append(SourceFile(
                path=source_file.path,
                name=source_file.name,
                source_code="\n".join(current_lines),
                extension=source_file.extension,
                start_line=current_start_line,
            ))
            current_lines = []
            current_tokens = 0
            current_start_line = absolute_start_line

        if not current_lines:
            current_start_line = absolute_start_line
        current_lines.extend(section_lines)
        current_tokens += section_tokens

    if current_lines:
        chunks.append(SourceFile(
            path=source_file.path,
            name=source_file.name,
            source_code="\n".join(current_lines),
            extension=source_file.extension,
            start_line=current_start_line,
        ))

    return chunks or [source_file]
