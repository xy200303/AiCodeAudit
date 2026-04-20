# 初始化LLM
import asyncio
import re
import time

from audit.chunker import split_source_file_semantic
from loguru import logger
from openai import AsyncOpenAI

from config import C
from models import CodeUnit, SourceFile
from audit.tree_sitter_parser import extract_code_units_with_tree_sitter, supports_tree_sitter
from prompt import build_agent_1_prompt, build_agent_2_prompt
from utils import (
    count_message_tokens,
    gen_line_code,
    get_available_text_token_budget,
    get_effective_max_input_tokens,
    parse_code_uint,
)

llm = AsyncOpenAI(
    base_url=C.openai.base_url,
    api_key=C.openai.api_key,
    timeout=C.openai.timeout_seconds,
)
_loop_semaphores = {}
_retry_warning_state = {}
_RETRY_WARNING_WINDOW_SECONDS = 3.0


def _is_likely_natural_language(text: str) -> bool:
    if not text:
        return True
    if len(text) > 120:
        return True
    separators = text.count(" ") + text.count("，") + text.count("。")
    if separators >= 4:
        return True
    if len(text) >= 12 and re.fullmatch(r"[\u4e00-\u9fff_a-zA-Z0-9]+", text) and "." not in text and ":" not in text:
        return True
    return False


def _target_name_supported_by_code(target_name: str, source_code: str) -> bool:
    if target_name in {"无外部依赖", ""}:
        return True
    if target_name.startswith("import:"):
        imported = target_name.split(":", 1)[1]
        return any(token and token in source_code for token in [imported, imported.split(".")[-1], imported.split("/")[-1]])

    candidate_tokens = []
    for token in re.split(r"[.:/\\]+", target_name):
        cleaned = token.strip()
        if cleaned:
            candidate_tokens.append(cleaned)
    if not candidate_tokens:
        return False
    return any(token in source_code for token in candidate_tokens[-2:])


def validate_agent_1_code_units(code_units: list[CodeUnit] | None, source_file: SourceFile) -> list[CodeUnit] | None:
    if not code_units:
        return None

    max_line = source_file.start_line + max(0, len(source_file.source_code.splitlines()) - 1)
    validated: list[CodeUnit] = []
    seen = set()

    for unit in code_units:
        if not unit.source_name or not unit.target_name:
            continue
        if _is_likely_natural_language(unit.source_name) or _is_likely_natural_language(unit.target_name):
            continue
        if unit.start_code_line < source_file.start_line or unit.end_code_line > max_line or unit.start_code_line > unit.end_code_line:
            continue
        if not unit.source_code.strip():
            continue
        if not _target_name_supported_by_code(unit.target_name, unit.source_code):
            continue

        signature = (
            unit.path,
            unit.source_name,
            unit.target_name,
            unit.start_code_line,
            unit.end_code_line,
        )
        if signature in seen:
            continue
        seen.add(signature)
        validated.append(unit)

    if code_units and not validated:
        logger.warning("Agent_1 结果全部被二次校验过滤: {}", source_file.path)
    elif len(validated) < len(code_units):
        logger.debug(
            "Agent_1 二次校验过滤了部分依赖: {} -> 原始 {} 条, 保留 {} 条",
            source_file.path,
            len(code_units),
            len(validated),
        )
    return validated or None


def get_llm_semaphore():
    loop = asyncio.get_running_loop()
    semaphore = _loop_semaphores.get(loop)
    if semaphore is None:
        semaphore = asyncio.Semaphore(max(1, C.openai.max_concurrency))
        _loop_semaphores[loop] = semaphore
    return semaphore


def _log_retry_warning(exc: Exception, attempt: int, backoff: float):
    error_text = str(exc).strip() or exc.__class__.__name__
    state_key = (attempt, exc.__class__.__name__, error_text)
    now = time.monotonic()
    state = _retry_warning_state.get(state_key)

    if state is None:
        _retry_warning_state[state_key] = {
            "window_start": now,
            "suppressed_count": 0,
            "summary_logged": False,
        }
        logger.warning(
            "OpenAI 请求失败，第 {}/{} 次将在 {} 秒后重试: {}",
            attempt,
            C.openai.max_retries,
            backoff,
            exc,
        )
        return

    if now - state["window_start"] <= _RETRY_WARNING_WINDOW_SECONDS:
        state["suppressed_count"] += 1
        if not state["summary_logged"]:
            logger.warning(
                "OpenAI 请求失败，第 {}/{} 次将在 {} 秒后重试: {}。短时间内检测到同类重复错误，后续 {} 秒内将合并显示。",
                attempt,
                C.openai.max_retries,
                backoff,
                exc,
                _RETRY_WARNING_WINDOW_SECONDS,
            )
            state["summary_logged"] = True
        return

    if state["suppressed_count"] > 0:
        logger.warning(
            "OpenAI 同类连接错误在 {} 秒窗口内额外出现 {} 次: {}",
            _RETRY_WARNING_WINDOW_SECONDS,
            state["suppressed_count"],
            exc,
        )

    _retry_warning_state[state_key] = {
        "window_start": now,
        "suppressed_count": 0,
        "summary_logged": False,
    }
    logger.warning(
        "OpenAI 请求失败，第 {}/{} 次将在 {} 秒后重试: {}",
        attempt,
        C.openai.max_retries,
        backoff,
        exc,
    )


async def chat_completion_text(text: str, prompt: str):
    messages = [
        {
            "role": "system",
            "content": prompt,
        },
        {
            "role": "user",
            "content": text,
        },
    ]
    return await chat_completion_messages(messages)


async def chat_completion_messages(messages) -> str:
    last_error = None
    max_input_tokens = get_effective_max_input_tokens()
    current_tokens = count_message_tokens(messages)
    if max_input_tokens is not None and current_tokens > max_input_tokens:
        raise RuntimeError(
            "请求消息过大: 当前约 {} tokens，模型 {} 上限 {} tokens。"
            "请在 config.yaml 中调小输入内容，或设置更合适的 openai.max_input_tokens。".format(
                current_tokens,
                C.openai.model,
                max_input_tokens,
            )
        )
    for attempt in range(1, C.openai.max_retries + 1):
        try:
            async with get_llm_semaphore():
                response = await llm.chat.completions.create(
                    model=C.openai.model,
                    messages=messages,
                )
            if response.choices and response.choices[0].message.content:
                return response.choices[0].message.content
            raise RuntimeError("No response from OpenAI")
        except Exception as exc:
            last_error = exc
            if attempt >= C.openai.max_retries:
                break
            backoff = C.openai.retry_backoff_seconds * attempt
            _log_retry_warning(exc, attempt, backoff)
            await asyncio.sleep(backoff)
    raise RuntimeError(f"OpenAI 请求最终失败: {last_error}") from last_error


async def agent_1(source_file: SourceFile):
    """
    使用语言模型解析代码中的依赖关系。
    """
    parse_engine = getattr(C.project, "dependency_parse_engine", "auto").lower()

    if parse_engine not in {"auto", "ast", "llm"}:
        logger.warning("未知 dependency_parse_engine 配置: {}，已回退为 auto", parse_engine)
        parse_engine = "auto"

    if parse_engine in {"auto", "ast"}:
        if supports_tree_sitter(source_file.extension):
            parsed = validate_agent_1_code_units(extract_code_units_with_tree_sitter(source_file), source_file)
            if parsed is not None:
                logger.debug("Agent_1 使用静态解析提取成功: {} -> {} 条依赖", source_file.path, len(parsed))
                return parsed
            if parse_engine == "auto":
                logger.warning("静态解析失败，auto 模式回退到 LLM 语义块提取: {}", source_file.path)
            else:
                logger.warning("静态解析失败，当前配置禁止回退到 LLM，返回空结果: {}", source_file.path)
                return None
        elif parse_engine == "ast":
            logger.warning("当前文件类型暂不支持静态解析，且配置为 ast-only，返回空结果: {}", source_file.path)
            return None
        elif parse_engine == "auto":
            logger.debug("当前文件类型未接入静态解析，auto 模式回退到 LLM: {}", source_file.path)

    prompt = build_agent_1_prompt(source_file.extension)
    if source_file.extension:
        logger.debug("Agent_1 使用语言增强规则: {}", source_file.extension.lower())

    llm_chunk_budget = get_available_text_token_budget(prompt) or getattr(C.openai, "max_per_tokens", None) or 4096
    llm_chunks = split_source_file_semantic(source_file, llm_chunk_budget)
    all_parsed = []
    for chunk in llm_chunks:
        numbered_code = gen_line_code(chunk.source_code, start_line=chunk.start_line)
        response = await chat_completion_text(numbered_code, prompt)
        parsed = parse_code_uint(
            code=chunk.source_code,
            path=chunk.path,
            name=chunk.name,
            input_text=response,
            base_line=chunk.start_line,
        )
        parsed = validate_agent_1_code_units(parsed, chunk)
        if parsed:
            all_parsed.extend(parsed)

    if all_parsed:
        logger.debug("Agent_1 LLM 解析成功: {} -> {} 条依赖", source_file.path, len(all_parsed))
        return all_parsed
    return None


async def agent_2(text: str) -> str:
    extensions = sorted(set(re.findall(r"\.(py|js|ts|java|go|php|c|cpp|cs)\b", text, flags=re.IGNORECASE)))
    normalized_extensions = [f".{ext.lower()}" for ext in extensions]
    prompt = build_agent_2_prompt(normalized_extensions)
    if normalized_extensions:
        logger.debug("Agent_2 使用语言增强规则: {}", ", ".join(normalized_extensions))
    return await chat_completion_text(text, prompt)
