from typing import List, Set, Tuple
from app.schemas.finding import ComparisonEntrySchema, SeverityEnum, MatchStateEnum
from app.claims.claim_extractor import TAXONOMY

CAPABILITY_SEVERITIES = {
    "Shell": SeverityEnum.CRITICAL,
    "Subprocess": SeverityEnum.HIGH,
    "Environment": SeverityEnum.HIGH,
    "Network": SeverityEnum.MEDIUM,
    "Filesystem": SeverityEnum.LOW,
    "Database": SeverityEnum.LOW
}

class ClaimBehaviorCorrelator:
    def correlate(
        self,
        claims: List[str],
        detected_behaviors: List[str]
    ) -> Tuple[List[ComparisonEntrySchema], List[str]]:
        """
        Correlates declared claims with detected behaviors.
        Returns:
            - List of ComparisonEntrySchema
            - List of undisclosed (hidden) capabilities
        """
        claims_set = {c.strip() for c in claims if c.strip()}
        behaviors_set = {b.strip() for b in detected_behaviors if b.strip()}
        
        comparisons: List[ComparisonEntrySchema] = []
        hidden_behaviors: List[str] = []

        # 1. Check all detected behaviors
        for b in sorted(list(behaviors_set)):
            matching_claim = next((c for c in claims_set if c.lower() == b.lower()), None)
            
            if matching_claim:
                comparisons.append(ComparisonEntrySchema(
                    claimed_capability=matching_claim,
                    detected_capability=b,
                    match_state=MatchStateEnum.MATCH,
                    severity=SeverityEnum.TRUSTED,
                    notes=f"Capability '{b}' is explicitly declared in documentation and matches observed code behavior."
                ))
            else:
                hidden_behaviors.append(b)
                default_sev = CAPABILITY_SEVERITIES.get(b, SeverityEnum.MEDIUM)
                comparisons.append(ComparisonEntrySchema(
                    claimed_capability="Not declared",
                    detected_capability=b,
                    match_state=MatchStateEnum.UNDISCLOSED,
                    severity=default_sev,
                    notes=f"Undisclosed capability: Code executes '{b}' operations, but no mention was found in repository documentation."
                ))

        # 2. Check claims that were never observed in code
        for c in sorted(list(claims_set)):
            matching_behavior = next((b for b in behaviors_set if b.lower() == c.lower()), None)
            if not matching_behavior:
                comparisons.append(ComparisonEntrySchema(
                    claimed_capability=c,
                    detected_capability="Not observed",
                    match_state=MatchStateEnum.MISMATCH,
                    severity=SeverityEnum.MEDIUM,
                    notes=f"Documentation claims '{c}' capability, but no corresponding code behavior was detected in scanned files."
                ))

        return comparisons, hidden_behaviors
