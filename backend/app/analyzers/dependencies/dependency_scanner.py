import re
import json
from typing import List, Tuple, Dict, Any
from app.intake.snapshot import SourceFile
from app.schemas.finding import VulnerabilitySchema, FindingSchema, SeverityEnum, FindingCategoryEnum
from app.analyzers.dependencies.osv_client import OSVClient

def parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    packages = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # match name==1.2.3 or name>=1.2.3
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+)", line)
        if match:
            packages.append({
                "ecosystem": "PyPI",
                "name": match.group(1),
                "version": match.group(2)
            })
    return packages

def parse_package_json(content: str) -> List[Dict[str, str]]:
    packages = []
    try:
        data = json.loads(content)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, ver in deps.items():
            # Clean ^ or ~ or >=
            clean_ver = re.sub(r"[^0-9\.]", "", ver)
            if clean_ver:
                packages.append({
                    "ecosystem": "npm",
                    "name": name,
                    "version": clean_ver
                })
    except Exception:
        pass
    return packages

class DependencyScanner:
    def __init__(self):
        self.osv_client = OSVClient()

    def scan_manifests(self, manifest_files: List[SourceFile]) -> Tuple[List[FindingSchema], List[VulnerabilitySchema]]:
        findings: List[FindingSchema] = []
        vulnerabilities: List[VulnerabilitySchema] = []

        all_pkgs: List[Dict[str, str]] = []
        for mf in manifest_files:
            fname = mf.path.lower()
            if "requirements.txt" in fname:
                all_pkgs.extend(parse_requirements_txt(mf.content))
            elif "package.json" in fname:
                all_pkgs.extend(parse_package_json(mf.content))

        if not all_pkgs:
            return findings, vulnerabilities

        results = self.osv_client.query_vulnerabilities(all_pkgs)

        for pkg, res in zip(all_pkgs, results):
            vulns = res.get("vulns", [])
            for v in vulns:
                vuln_id = v.get("id", "UNKNOWN-CVE")
                summary = v.get("summary", "Known security vulnerability in upstream dependency")
                
                # Severity determination
                sev = SeverityEnum.HIGH
                database_specific = v.get("database_specific", {})
                severity_str = database_specific.get("severity", "").upper()
                if "CRITICAL" in severity_str:
                    sev = SeverityEnum.CRITICAL
                elif "HIGH" in severity_str:
                    sev = SeverityEnum.HIGH
                elif "MODERATE" in severity_str or "MEDIUM" in severity_str:
                    sev = SeverityEnum.MEDIUM
                elif "LOW" in severity_str:
                    sev = SeverityEnum.LOW

                fixed_version = None
                affected = v.get("affected", [])
                if affected and "ranges" in affected[0]:
                    for r in affected[0]["ranges"]:
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                                break

                vuln_model = VulnerabilitySchema(
                    package_name=pkg["name"],
                    version=pkg["version"],
                    cve_id=vuln_id,
                    severity=sev.value.upper(),
                    summary=summary,
                    fixed_version=fixed_version,
                    source="osv.dev"
                )
                vulnerabilities.append(vuln_model)

                findings.append(FindingSchema(
                    category=FindingCategoryEnum.DEPENDENCY,
                    capability_label="KnownVulnerability",
                    severity=sev,
                    confidence="high",
                    file_path=f"dependency:{pkg['ecosystem']}:{pkg['name']}",
                    snippet=f"{pkg['name']}=={pkg['version']}",
                    description=f"{vuln_id} ({pkg['name']}@{pkg['version']}): {summary}",
                    source="dependency"
                ))

        return findings, vulnerabilities
