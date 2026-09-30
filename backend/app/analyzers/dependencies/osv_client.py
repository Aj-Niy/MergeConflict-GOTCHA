import re
import json
from typing import List, Dict, Any, Optional
import httpx
from app.schemas.finding import VulnerabilitySchema, FindingSchema, SeverityEnum, FindingCategoryEnum

class OSVClient:
    BASE_URL = "https://api.osv.dev/v1/querybatch"

    def query_vulnerabilities(self, packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        packages format: [{"ecosystem": "PyPI"|"npm", "name": "...", "version": "..."}]
        """
        if not packages:
            return []
        
        queries = []
        for pkg in packages:
            queries.append({
                "package": {
                    "name": pkg["name"],
                    "ecosystem": pkg["ecosystem"]
                },
                "version": pkg["version"]
            })

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(self.BASE_URL, json={"queries": queries})
                if res.status_code == 200:
                    data = res.json()
                    return data.get("results", [])
        except Exception as e:
            print(f"OSV.dev API query skipped/unavailable: {e}")
            return []

        return []
