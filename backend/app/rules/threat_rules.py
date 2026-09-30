from typing import List
from app.schemas.finding import FindingSchema, SeverityEnum, FindingCategoryEnum

class ThreatRuleEngine:
    def evaluate_rules(
        self,
        findings: List[FindingSchema],
        claims: List[str],
        hidden_behaviors: List[str]
    ) -> List[FindingSchema]:
        threat_findings: List[FindingSchema] = []
        
        # Group findings by file_path
        by_file = {}
        for f in findings:
            if f.file_path:
                by_file.setdefault(f.file_path, []).append(f)

        has_secrets = any(f.category == FindingCategoryEnum.SECRET for f in findings)
        has_network = any(f.capability_label == "Network" for f in findings)
        has_shell = any(f.capability_label == "Shell" for f in findings)
        has_env = any(f.capability_label == "Environment" for f in findings)
        has_dynamic = any(f.capability_label in ("NativeCodeExecution", "DynamicImport", "Deserialization") for f in findings)

        # Rule 1: Secret + Network Exfiltration
        if has_secrets and has_network:
            threat_findings.append(FindingSchema(
                category=FindingCategoryEnum.THREAT_RULE,
                capability_label="CredentialExfiltrationRisk",
                severity=SeverityEnum.CRITICAL,
                confidence="high",
                file_path="cross-file",
                description="High Risk Threat Path: Hardcoded secrets co-occur with outbound network capabilities, posing immediate risk of token exfiltration.",
                source="threat_rule"
            ))

        # Rule 2: Per-file Environment Read + Network Request
        for fpath, file_finds in by_file.items():
            f_caps = {f.capability_label for f in file_finds if f.capability_label}
            if "Environment" in f_caps and "Network" in f_caps:
                env_line = next((f.line_number for f in file_finds if f.capability_label == "Environment"), None)
                net_line = next((f.line_number for f in file_finds if f.capability_label == "Network"), None)
                threat_findings.append(FindingSchema(
                    category=FindingCategoryEnum.THREAT_RULE,
                    capability_label="EnvironmentStealerPattern",
                    severity=SeverityEnum.HIGH,
                    confidence="high",
                    file_path=fpath,
                    line_number=env_line or net_line,
                    description=f"Candidate Exfiltration Path: File '{fpath}' reads environment variables and executes outbound network requests.",
                    source="threat_rule"
                ))

        # Rule 3: Hidden / Undisclosed Shell Execution
        if "Shell" in hidden_behaviors or ("Subprocess" in hidden_behaviors and any(f.severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL) for f in findings if f.capability_label == "Subprocess")):
            threat_findings.append(FindingSchema(
                category=FindingCategoryEnum.THREAT_RULE,
                capability_label="UndisclosedShellExecution",
                severity=SeverityEnum.CRITICAL,
                confidence="high",
                file_path="repository-wide",
                description="Stealth Command Execution: Arbitrary system commands/subprocesses are spawned in code without any disclosure in project documentation.",
                source="threat_rule"
            ))

        # Rule 4: Dynamic Code Execution + Subprocess / Network
        if has_dynamic and (has_shell or has_network):
            threat_findings.append(FindingSchema(
                category=FindingCategoryEnum.THREAT_RULE,
                capability_label="DynamicBackdoorRisk",
                severity=SeverityEnum.HIGH,
                confidence="high",
                file_path="repository-wide",
                description="Unsafe Execution Vector: Dynamic code execution/unpickling detected alongside network or process spawning capabilities.",
                source="threat_rule"
            ))

        return threat_findings
