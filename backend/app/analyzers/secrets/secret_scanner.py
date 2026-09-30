import re
from typing import List, Tuple
from app.schemas.finding import FindingSchema, SecretFindingSchema, SeverityEnum, FindingCategoryEnum

SECRET_PATTERNS = [
    ("OpenAI API Key", r"\bsk-[a-zA-Z0-9_-]{20,60}\b", SeverityEnum.CRITICAL),
    ("GitHub Personal Access Token", r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}\b", SeverityEnum.CRITICAL),
    ("AWS Access Key ID", r"\bAKIA[0-9A-Z]{16}\b", SeverityEnum.HIGH),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*=\s*['\"][a-zA-Z0-9/+=]{40}['\"]", SeverityEnum.CRITICAL),
    ("Slack Token", r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b", SeverityEnum.HIGH),
    ("Stripe API Key", r"\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}\b", SeverityEnum.HIGH),
    ("Private Key Header", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", SeverityEnum.CRITICAL),
    ("JWT Secret / Bearer Token", r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b", SeverityEnum.MEDIUM),
    ("Crypto Private Key", r"\b0x[a-fA-F0-9]{64}\b", SeverityEnum.HIGH),
    ("Generic Bearer / API Token", r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{24,128}['\"]", SeverityEnum.HIGH),
]

def redact_secret(raw_val: str) -> str:
    cleaned = raw_val.strip("'\"")
    if len(cleaned) <= 6:
        return "****"
    return f"{cleaned[:3]}...{cleaned[-3:]}"

class SecretScanner:
    def scan_content(self, content_str: str, file_path: str) -> Tuple[List[FindingSchema], List[SecretFindingSchema]]:
        findings: List[FindingSchema] = []
        secret_findings: List[SecretFindingSchema] = []

        lines = content_str.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            matched_spans = []
            for secret_type, pattern, severity in SECRET_PATTERNS:
                matches = list(re.finditer(pattern, line))
                for match in matches:
                    span = (match.start(), match.end())
                    # Check for any overlapping span with already matched higher-priority specific pattern
                    if any(s[0] < span[1] and s[1] > span[0] for s in matched_spans):
                        continue
                    matched_spans.append(span)

                    raw_val = match.group(0)
                    redacted = redact_secret(raw_val)

                    secret_model = SecretFindingSchema(
                        secret_type=secret_type,
                        file_path=file_path,
                        line_number=line_idx,
                        redacted_value=redacted,
                        confidence="high"
                    )
                    secret_findings.append(secret_model)

                    finding_model = FindingSchema(
                        category=FindingCategoryEnum.SECRET,
                        capability_label="SecretExposure",
                        severity=severity,
                        confidence="high",
                        file_path=file_path,
                        line_number=line_idx,
                        snippet=f"{line[:match.start()]} [REDACTED SECRET: {redacted}] {line[match.end():]}".strip()[:200],
                        description=f"Hardcoded secret detected: {secret_type} ({redacted})",
                        source="secret"
                    )
                    findings.append(finding_model)

        return findings, secret_findings
