import ast
from typing import List, Set, Dict, Any, Optional
from app.schemas.finding import FindingSchema, SeverityEnum, FindingCategoryEnum

NETWORK_MODULES = {
    "requests", "urllib", "urllib3", "httpx", "socket", "aiohttp", "websockets", "paramiko", "ftplib", "smtplib"
}

DATABASE_MODULES = {
    "sqlite3", "mysql", "psycopg2", "psycopg", "pymongo", "redis", "sqlalchemy", "peewee", "asyncpg", "tortoise"
}

DYNAMIC_EXECUTION = {
    "eval", "exec", "compile"
}

SUSPICIOUS_SUBPROCESS_ATTRS = {
    "system", "popen", "spawn", "execv", "execve", "execl", "execlp"
}

class PythonAstAnalyzer:
    def __init__(self):
        self.findings: List[FindingSchema] = []
        self.capabilities: Set[str] = set()

    def analyze_code(self, code_str: str, file_path: str = "source.py") -> List[FindingSchema]:
        self.findings = []
        self.capabilities = set()
        
        try:
            tree = ast.parse(code_str, filename=file_path)
        except SyntaxError as e:
            return self.findings
        except Exception:
            return self.findings

        lines = code_str.splitlines()

        def get_snippet(lineno: Optional[int]) -> Optional[str]:
            if lineno and 1 <= lineno <= len(lines):
                return lines[lineno - 1].strip()
            return None

        class Visitor(ast.NodeVisitor):
            def __init__(v_self):
                super().__init__()

            def visit_Import(v_self, node: ast.Import):
                for alias in node.names:
                    root_name = alias.name.split(".")[0]
                    lineno = getattr(node, "lineno", None)
                    snippet = get_snippet(lineno)

                    if root_name in NETWORK_MODULES:
                        self.capabilities.add("Network")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Network",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Network module '{alias.name}' imported",
                            source="behavior"
                        ))
                    elif root_name in DATABASE_MODULES:
                        self.capabilities.add("Database")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Database",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Database module '{alias.name}' imported",
                            source="behavior"
                        ))
                    elif root_name == "subprocess":
                        self.capabilities.add("Subprocess")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Subprocess",
                            severity=SeverityEnum.MEDIUM,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="Subprocess execution module imported",
                            source="behavior"
                        ))
                    elif root_name in ("shutil", "pathlib", "tempfile"):
                        self.capabilities.add("Filesystem")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Filesystem",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Filesystem module '{alias.name}' imported",
                            source="behavior"
                        ))
                    elif root_name in ("os", "sys"):
                        self.capabilities.add("Environment")
                    elif root_name == "ctypes":
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="NativeCodeExecution",
                            severity=SeverityEnum.HIGH,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="ctypes foreign function interface imported (allows raw memory & native code execution)",
                            source="behavior"
                        ))
                    elif root_name == "pickle":
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="Deserialization",
                            severity=SeverityEnum.MEDIUM,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="pickle module imported (unsafe deserialization risk)",
                            source="behavior"
                        ))
                    elif root_name in ("importlib", "__import__"):
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="DynamicImport",
                            severity=SeverityEnum.MEDIUM,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="Dynamic module loading / importlib imported",
                            source="behavior"
                        ))
                v_self.generic_visit(node)

            def visit_ImportFrom(v_self, node: ast.ImportFrom):
                if node.module:
                    root_name = node.module.split(".")[0]
                    lineno = getattr(node, "lineno", None)
                    snippet = get_snippet(lineno)

                    if root_name in NETWORK_MODULES:
                        self.capabilities.add("Network")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Network",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Network module '{node.module}' imported",
                            source="behavior"
                        ))
                    elif root_name in DATABASE_MODULES:
                        self.capabilities.add("Database")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Database",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Database module '{node.module}' imported",
                            source="behavior"
                        ))
                    elif root_name == "subprocess":
                        self.capabilities.add("Subprocess")
                    elif root_name == "ctypes":
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="NativeCodeExecution",
                            severity=SeverityEnum.HIGH,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="ctypes functions imported",
                            source="behavior"
                        ))
                v_self.generic_visit(node)

            def visit_Call(v_self, node: ast.Call):
                lineno = getattr(node, "lineno", None)
                snippet = get_snippet(lineno)

                # Direct function calls: eval(), exec(), open(), __import__()
                if isinstance(node.func, ast.Name):
                    func_id = node.func.id
                    if func_id in DYNAMIC_EXECUTION:
                        self.capabilities.add("Shell")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="Shell",
                            severity=SeverityEnum.CRITICAL,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Dangerous dynamic code execution via `{func_id}()`",
                            source="behavior"
                        ))
                    elif func_id == "open":
                        self.capabilities.add("Filesystem")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Filesystem",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="File I/O operation via `open()`",
                            source="behavior"
                        ))
                    elif func_id == "__import__":
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="DynamicImport",
                            severity=SeverityEnum.HIGH,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="Dynamic runtime import via `__import__()`",
                            source="behavior"
                        ))

                # Attribute calls: os.system, subprocess.run, requests.get, pickle.loads, etc.
                elif isinstance(node.func, ast.Attribute):
                    attr = node.func.attr
                    
                    if attr in ("get", "post", "put", "delete", "request", "urlopen", "connect", "send"):
                        self.capabilities.add("Network")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Network",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Outbound network request call `.{attr}()`",
                            source="behavior"
                        ))
                    elif attr in ("run", "Popen", "call", "check_output", "check_call"):
                        self.capabilities.add("Subprocess")
                        
                        # Check if shell=True is passed
                        has_shell_true = any(
                            isinstance(kw, ast.keyword) and kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                            for kw in node.keywords
                        )
                        sev = SeverityEnum.HIGH if has_shell_true else SeverityEnum.MEDIUM
                        desc = f"Subprocess spawned via `.{attr}()`" + (" with shell=True (Command Injection Risk)" if has_shell_true else "")
                        
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC if has_shell_true else FindingCategoryEnum.CAPABILITY,
                            capability_label="Subprocess",
                            severity=sev,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=desc,
                            source="behavior"
                        ))
                    elif attr in SUSPICIOUS_SUBPROCESS_ATTRS:
                        self.capabilities.add("Shell")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="Shell",
                            severity=SeverityEnum.CRITICAL,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"System command / shell execution via `os.{attr}()`",
                            source="behavior"
                        ))
                    elif attr == "getenv":
                        self.capabilities.add("Environment")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Environment",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="Environment variable read via `os.getenv()`",
                            source="behavior"
                        ))
                    elif attr in ("remove", "unlink", "rename", "rmdir", "removedirs", "mkdir", "makedirs", "write_bytes", "write_text"):
                        self.capabilities.add("Filesystem")
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.CAPABILITY,
                            capability_label="Filesystem",
                            severity=SeverityEnum.INFO,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description=f"Filesystem mutation call `.{attr}()`",
                            source="behavior"
                        ))
                    elif attr in ("loads", "load") and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                        self.findings.append(FindingSchema(
                            category=FindingCategoryEnum.STATIC,
                            capability_label="Deserialization",
                            severity=SeverityEnum.HIGH,
                            confidence="high",
                            file_path=file_path,
                            line_number=lineno,
                            snippet=snippet,
                            description="Unsafe object unpickling via `pickle.loads()` (Arbitrary Code Execution risk)",
                            source="behavior"
                        ))

                v_self.generic_visit(node)

            def visit_Attribute(v_self, node: ast.Attribute):
                lineno = getattr(node, "lineno", None)
                snippet = get_snippet(lineno)
                if node.attr == "environ":
                    self.capabilities.add("Environment")
                    self.findings.append(FindingSchema(
                        category=FindingCategoryEnum.CAPABILITY,
                        capability_label="Environment",
                        severity=SeverityEnum.INFO,
                        confidence="high",
                        file_path=file_path,
                        line_number=lineno,
                        snippet=snippet,
                        description="Environment access via `os.environ`",
                        source="behavior"
                    ))
                v_self.generic_visit(node)

        visitor = Visitor()
        visitor.visit(tree)
        return self.findings
