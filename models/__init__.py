from pydantic import BaseModel, Field
from typing import List, Optional

class SourceFile(BaseModel):
    path: str
    name: str
    source_code: str
    extension: str
    start_line: int = 1

class SourceDir(BaseModel):
    path: str
    name: str
    source_dirs: Optional[List['SourceDir']] = Field(default_factory=list)
    source_files: Optional[List[SourceFile]] = Field(default_factory=list)


class OpenAIConfig(BaseModel):
    api_key: str
    base_url: str
    model: str
    max_input_tokens: int | None = None
    max_per_tokens: int | None = None
    request_overhead_tokens: int = 512
    timeout_seconds: float = 60.0
    max_retries: int = 3
    retry_backoff_seconds: float = 2.0
    max_concurrency: int = 5

class ProjectConfig(BaseModel):
    config_file_ext: List[str] = Field(default_factory=list)
    exclude_dir: List[str] = Field(default_factory=list)
    exclude_max_file_size: float
    source_file_ext: List[str] = Field(default_factory=list)
    dependency_parse_engine: str = "auto"
    audit_context_depth: int = 2
    max_audit_nodes: int = 12
    dependency_tree_max_branches: int = 3
    dependency_context_max_focus_paths: int = 6
    agent2_failure_rate_threshold: float = 0.3
    agent2_candidate_score_threshold: int = 8

class Config(BaseModel):
    openai: OpenAIConfig
    project: ProjectConfig


class CodeUnit(BaseModel):
    source_code:str
    start_code_line:int
    end_code_line:int
    name:str
    path:str
    source_name:str
    target_name:str
    source_desc:str


