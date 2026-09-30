import io
import os
import tarfile
import tempfile
import re
from pathlib import Path
from typing import Tuple, List, Optional
import httpx
import requests
from app.config import settings
from app.intake.snapshot import RepoSnapshot, SourceFile

SUPPORTED_SOURCE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".sh": "shell",
    ".bash": "shell"
}

MANIFEST_FILENAMES = {
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "cargo.toml"
}

def parse_github_url(url: str) -> Tuple[str, str]:
    cleaned = url.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    
    # Match github.com/owner/repo
    pattern = r"github\.com[/:]([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)"
    match = re.search(pattern, cleaned)
    if match:
        return match.group(1), match.group(2)
    
    parts = [p for p in cleaned.split("/") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    
    raise ValueError(f"Invalid repository URL: {url}")

def is_safe_tar_member(member: tarfile.TarInfo, target_dir: str) -> bool:
    # Reject absolute paths or paths with '..' traversal
    target_path = os.path.abspath(os.path.join(target_dir, member.name))
    common = os.path.commonpath([target_dir, target_path])
    if common != target_dir:
        return False
    # Check for hard links or dangerous symlinks pointing outside
    if member.islnk() or member.issym():
        link_target = os.path.abspath(os.path.join(target_dir, member.linkname))
        if os.path.commonpath([target_dir, link_target]) != target_dir:
            return False
    return True

def fetch_repository_snapshot(url: str) -> RepoSnapshot:
    """
    Fetches a repository snapshot safely via GitHub tarball or fallback.
    If URL points to a local directory or sample, handles it seamlessly.
    """
    if os.path.exists(url) and os.path.isdir(url):
        return load_local_snapshot(url)
    
    owner, repo_name = parse_github_url(url)
    headers = {
        "User-Agent": "GOTCHA-Trust-Engine/2.0",
        "Accept": "application/vnd.github.v3+json"
    }
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    tarball_url = f"https://codeload.github.com/{owner}/{repo_name}/tar.gz/HEAD"
    
    # Try fetching tarball
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get(tarball_url, headers=headers)
            if resp.status_code == 200:
                return extract_snapshot_from_tarball(
                    tar_bytes=resp.content,
                    url=url,
                    owner=owner,
                    name=repo_name
                )
    except Exception as e:
        print(f"Tarball intake warning: {e}. Falling back to GitHub REST API / Raw...")

    # Fallback to REST API fetch
    return fetch_via_github_api(url, owner, repo_name, headers)

def extract_snapshot_from_tarball(
    tar_bytes: bytes,
    url: str,
    owner: str,
    name: str
) -> RepoSnapshot:
    source_files: List[SourceFile] = []
    manifest_files: List[SourceFile] = []
    readme_content = ""
    total_size = 0
    total_files = 0
    max_total_bytes = settings.MAX_TOTAL_SIZE_MB * 1024 * 1024
    max_file_bytes = settings.MAX_FILE_SIZE_KB * 1024

    with tempfile.TemporaryDirectory() as temp_dir:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
            members = tar.getmembers()
            # Find common root folder in tar
            root_prefix = ""
            if members and "/" in members[0].name:
                root_prefix = members[0].name.split("/")[0] + "/"

            for member in members:
                if not member.isfile():
                    continue
                if not is_safe_tar_member(member, temp_dir):
                    continue

                rel_path = member.name
                if root_prefix and rel_path.startswith(root_prefix):
                    rel_path = rel_path[len(root_prefix):]

                if not rel_path or rel_path.startswith(".git/"):
                    continue

                total_files += 1
                if total_files > settings.MAX_FILES:
                    break

                if total_size + member.size > max_total_bytes:
                    break

                filename = os.path.basename(rel_path)
                ext = Path(filename).suffix.lower()

                f = tar.extractfile(member)
                if not f:
                    continue
                
                content_bytes = f.read(max_file_bytes + 1)
                if len(content_bytes) > max_file_bytes:
                    continue # Skip oversized single files

                try:
                    content_str = content_bytes.decode("utf-8", errors="replace")
                except Exception:
                    continue

                total_size += len(content_bytes)

                # Check README
                if filename.lower() in ("readme.md", "readme.rst", "readme.txt", "readme"):
                    if not readme_content or filename.lower() == "readme.md":
                        readme_content = content_str

                # Check Manifest
                if filename.lower() in MANIFEST_FILENAMES:
                    manifest_files.append(SourceFile(
                        path=rel_path,
                        language="manifest",
                        content=content_str,
                        size_bytes=len(content_bytes)
                    ))

                # Check Source File
                if ext in SUPPORTED_SOURCE_EXTENSIONS:
                    source_files.append(SourceFile(
                        path=rel_path,
                        language=SUPPORTED_SOURCE_EXTENSIONS[ext],
                        content=content_str,
                        size_bytes=len(content_bytes)
                    ))

    return RepoSnapshot(
        url=url,
        owner=owner,
        name=name,
        readme_content=readme_content,
        manifest_files=manifest_files,
        files=source_files,
        total_files_scanned=len(source_files) + len(manifest_files),
        total_size_bytes=total_size
    )

def fetch_via_github_api(url: str, owner: str, name: str, headers: dict) -> RepoSnapshot:
    source_files: List[SourceFile] = []
    manifest_files: List[SourceFile] = []
    readme_content = ""
    total_size = 0

    # Fetch README
    readme_endpoint = f"https://api.github.com/repos/{owner}/{name}/readme"
    try:
        r = requests.get(readme_endpoint, headers={**headers, "Accept": "application/vnd.github.raw"}, timeout=15)
        if r.status_code == 200:
            readme_content = r.text
    except Exception as e:
        print(f"Error fetching readme: {e}")

    # Recursive contents walk
    def walk(path=""):
        nonlocal total_size
        if len(source_files) >= settings.MAX_FILES:
            return
        endpoint = f"https://api.github.com/repos/{owner}/{name}/contents/{path}"
        try:
            res = requests.get(endpoint, headers=headers, timeout=15)
            if res.status_code != 200:
                return
            items = res.json()
            if isinstance(items, dict):
                items = [items]
            for item in items:
                if len(source_files) >= settings.MAX_FILES:
                    break
                if item.get("type") == "dir":
                    if not item.get("name", "").startswith("."):
                        walk(item.get("path", ""))
                elif item.get("type") == "file":
                    fname = item.get("name", "")
                    ext = Path(fname).suffix.lower()
                    download_url = item.get("download_url")
                    if not download_url:
                        continue
                    
                    if ext in SUPPORTED_SOURCE_EXTENSIONS or fname.lower() in MANIFEST_FILENAMES:
                        raw_res = requests.get(download_url, headers=headers, timeout=15)
                        if raw_res.status_code == 200:
                            content = raw_res.text
                            size = len(content.encode("utf-8"))
                            total_size += size
                            
                            if fname.lower() in MANIFEST_FILENAMES:
                                manifest_files.append(SourceFile(
                                    path=item.get("path", fname),
                                    language="manifest",
                                    content=content,
                                    size_bytes=size
                                ))
                            if ext in SUPPORTED_SOURCE_EXTENSIONS:
                                source_files.append(SourceFile(
                                    path=item.get("path", fname),
                                    language=SUPPORTED_SOURCE_EXTENSIONS[ext],
                                    content=content,
                                    size_bytes=size
                                ))
        except Exception as e:
            print(f"Walk error: {e}")

    try:
        walk()
    except Exception as e:
        print(f"GitHub API walk completed with notes: {e}")

    return RepoSnapshot(
        url=url,
        owner=owner,
        name=name,
        readme_content=readme_content,
        manifest_files=manifest_files,
        files=source_files,
        total_files_scanned=len(source_files) + len(manifest_files),
        total_size_bytes=total_size
    )

def load_local_snapshot(dir_path: str) -> RepoSnapshot:
    source_files: List[SourceFile] = []
    manifest_files: List[SourceFile] = []
    readme_content = ""
    total_size = 0
    p = Path(dir_path)

    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules" and d != "venv"]
        for file in files:
            if file.startswith("."):
                continue
            full_path = Path(root) / file
            rel_path = str(full_path.relative_to(p))
            ext = full_path.suffix.lower()

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
                size = len(content.encode("utf-8"))
                total_size += size

                if file.lower() in ("readme.md", "readme.txt", "readme"):
                    readme_content = content

                if file.lower() in MANIFEST_FILENAMES:
                    manifest_files.append(SourceFile(
                        path=rel_path,
                        language="manifest",
                        content=content,
                        size_bytes=size
                    ))

                if ext in SUPPORTED_SOURCE_EXTENSIONS:
                    source_files.append(SourceFile(
                        path=rel_path,
                        language=SUPPORTED_SOURCE_EXTENSIONS[ext],
                        content=content,
                        size_bytes=size
                    ))
            except Exception:
                continue

    return RepoSnapshot(
        url=f"file://{os.path.abspath(dir_path)}",
        owner="local",
        name=p.name,
        readme_content=readme_content,
        manifest_files=manifest_files,
        files=source_files,
        total_files_scanned=len(source_files) + len(manifest_files),
        total_size_bytes=total_size
    )
