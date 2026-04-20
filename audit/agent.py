# 初始化LLM
import asyncio
import re

from loguru import logger
from openai import AsyncOpenAI

from config import C
from models import SourceFile
from audit.tree_sitter_parser import extract_code_units_with_tree_sitter, supports_tree_sitter
from prompt import build_agent_1_prompt, build_agent_2_prompt
from utils import (
    count_message_tokens,
    gen_line_code,
    get_effective_max_input_tokens,
    parse_code_uint,
)

llm = AsyncOpenAI(
    base_url=C.openai.base_url,
    api_key=C.openai.api_key,
    timeout=C.openai.timeout_seconds,
)
_loop_semaphores = {}


def get_llm_semaphore():
    loop = asyncio.get_running_loop()
    semaphore = _loop_semaphores.get(loop)
    if semaphore is None:
        semaphore = asyncio.Semaphore(max(1, C.openai.max_concurrency))
        _loop_semaphores[loop] = semaphore
    return semaphore


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
            logger.warning(
                "OpenAI 请求失败，第 {}/{} 次将在 {} 秒后重试: {}",
                attempt,
                C.openai.max_retries,
                backoff,
                exc,
            )
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
            parsed = extract_code_units_with_tree_sitter(source_file)
            if parsed is not None:
                logger.debug("Agent_1 使用静态解析提取成功: {} -> {} 条依赖", source_file.path, len(parsed))
                return parsed
            logger.warning("静态解析失败，当前配置禁止回退到 LLM，返回空结果: {}", source_file.path)
            return None
        elif parse_engine == "ast":
            logger.warning("当前文件类型暂不支持静态解析，且配置为 ast-only，返回空结果: {}", source_file.path)
            return None
        elif parse_engine == "auto":
            logger.debug("当前文件类型未接入静态解析，auto 模式回退到 LLM: {}", source_file.path)

    numbered_code = gen_line_code(source_file.source_code, start_line=source_file.start_line)
    prompt = build_agent_1_prompt(source_file.extension)
    if source_file.extension:
        logger.debug("Agent_1 使用语言增强规则: {}", source_file.extension.lower())
    response = await chat_completion_text(numbered_code, prompt)
    parsed = parse_code_uint(
        code=source_file.source_code,
        path=source_file.path,
        name=source_file.name,
        input_text=response,
        base_line=source_file.start_line,
    )
    if parsed:
        logger.debug("Agent_1 解析成功: {} -> {} 条依赖", source_file.path, len(parsed))
    return parsed


async def agent_2(text: str) -> str:
    extensions = sorted(set(re.findall(r"\.(py|js|ts|java|go|php|c|cpp|cs)\b", text, flags=re.IGNORECASE)))
    normalized_extensions = [f".{ext.lower()}" for ext in extensions]
    prompt = build_agent_2_prompt(normalized_extensions)
    if normalized_extensions:
        logger.debug("Agent_2 使用语言增强规则: {}", ", ".join(normalized_extensions))
    return await chat_completion_text(text, prompt)
