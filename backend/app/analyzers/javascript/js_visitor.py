import re
from typing import List, Set, Optional
from app.schemas.finding import FindingSchema, SeverityEnum, FindingCategoryEnum

JS_NETWORK_PATTERNS = [
    (r"import\s+.*?\s+from\s+['\"](axios|node-fetch|got|superagent|undici|http|https|net|ws|socket\.io)['\"]", "Network", SeverityEnum.INFO, "Outbound network / HTTP client import"),
    (r"require\(\s*['\"](axios|node-fetch|got|superagent|undici|http|https|net|ws|socket\.io)['\"]\s*\)", "Network", SeverityEnum.INFO, "Outbound network / HTTP client require"),
    (r"\b(fetch|axios\.(get|post|put|delete|patch|request))\s*\(", "Network", SeverityEnum.INFO, "Network request invocation"),
    (r"\bnew\s+WebSocket\s*\(", "Network", SeverityEnum.INFO, "WebSocket connection initialization"),
]

JS_FS_PATTERNS = [
    (r"import\s+.*?\s+from\s+['\"](fs|fs/promises|path)['\"]", "Filesystem", SeverityEnum.INFO, "Filesystem module import"),
    (r"require\(\s*['\"](fs|fs/promises)['\"]\s*\)", "Filesystem", SeverityEnum.INFO, "Filesystem module require"),
    (r"\bfs\.(readFile|writeFile|appendFile|unlink|rm|mkdir|readdir|createReadStream|createWriteStream)(Sync)?\s*\(", "Filesystem", SeverityEnum.INFO, "File I/O operation"),
]

JS_ENV_PATTERNS = [
    (r"\bprocess\.env(\.[a-zA-Z0-9_]+|\[['\"][a-zA-Z0-9_]+['\"]\])", "Environment", SeverityEnum.INFO, "Environment variable access via `process.env`"),
]

JS_SUBPROCESS_PATTERNS = [
    (r"import\s+.*?\s+from\s+['\"](child_process)['\"]", "Subprocess", SeverityEnum.MEDIUM, "Subprocess module import"),
    (r"require\(\s*['\"](child_process)['\"]\s*\)", "Subprocess", SeverityEnum.MEDIUM, "Subprocess module require"),
    (r"\b(exec|execSync|spawn|spawnSync|fork)\s*\(", "Subprocess", SeverityEnum.HIGH, "Process execution call"),
]

JS_DYNAMIC_EXEC_PATTERNS = [
    (r"\beval\s*\(", "Shell", SeverityEnum.CRITICAL, "Dangerous dynamic code evaluation via `eval()`"),
    (r"\bnew\s+Function\s*\(", "Shell", SeverityEnum.CRITICAL, "Dynamic code constructor via `new Function()`"),
]

JS_DATABASE_PATTERNS = [
    (r"import\s+.*?\s+from\s+['\"](pg|mysql|mysql2|sqlite3|better-sqlite3|mongoose|typeorm|prisma|ioredis|mongodb)['\"]", "Database", SeverityEnum.INFO, "Database driver import"),
    (r"require\(\s*['\"](pg|mysql|mysql2|sqlite3|better-sqlite3|mongoose|typeorm|prisma|ioredis|mongodb)['\"]\s*\)", "Database", SeverityEnum.INFO, "Database driver require"),
]

class JavaScriptAnalyzer:
    def __init__(self):
        self.findings: List[FindingSchema] = []
        self.capabilities: Set[str] = set()

    def analyze_code(self, code_str: str, file_path: str = "source.js") -> List[FindingSchema]:
        self.findings = []
        self.capabilities = set()

        lines = code_str.splitlines()

        all_rules = (
            JS_NETWORK_PATTERNS
            + JS_FS_PATTERNS
            + JS_ENV_PATTERNS
            + JS_SUBPROCESS_PATTERNS
            + JS_DYNAMIC_EXEC_PATTERNS
            + JS_DATABASE_PATTERNS
        )

        for line_idx, line in enumerate(lines, start=1):
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("//") or trimmed.startswith("/*"):
                continue

            for pattern, capability, severity, description in all_rules:
                if re.search(pattern, line):
                    self.capabilities.add(capability)
                    category = FindingCategoryEnum.STATIC if severity in (SeverityEnum.CRITICAL, SeverityEnum.HIGH) else FindingCategoryEnum.CAPABILITY
                    
                    self.findings.append(FindingSchema(
                        category=category,
                        capability_label=capability,
                        severity=severity,
                        confidence="high",
                        file_path=file_path,
                        line_number=line_idx,
                        snippet=trimmed[:200],
                        description=description,
                        source="behavior"
                    ))

        return self.findings
