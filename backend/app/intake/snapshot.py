from typing import List, Optional
from pydantic import BaseModel

class SourceFile(BaseModel):
    path: str
    language: str
    content: str
    size_bytes: int

class RepoSnapshot(BaseModel):
    url: str
    owner: str
    name: str
    default_branch: str = "main"
    commit_sha: Optional[str] = None
    readme_content: str = ""
    manifest_files: List[SourceFile] = []
    files: List[SourceFile] = []
    total_files_scanned: int = 0
    total_size_bytes: int = 0
