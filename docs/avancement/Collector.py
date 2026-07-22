import requests
import time
from datetime import datetime, timedelta

NVD_API_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_recent_cves(days_back: int =7, results_per_page: int = 50) -> list[dict]:
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days = days_back)

    params = {
        "pubStartDate" : start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate" : end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage":results_per_page,
    }

    response = requests.get(NVD_API_URL, params=params, timeout=30)
    response.raise_for_status

    data = response.json()
    return data.get("vulnerabilities",[])

def get_cve_by_id(cve_id: str) -> dict | None:

    params = {"cveId": cve_id}
    response = requests.get(NVD_API_URL, params=params, timeout=30)
    response.raise_for_status()
 
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])
    return vulnerabilities[0] if vulnerabilities else None

def collect_and_save(days_back: int = 7 , output_path: str ="data/raw_cves.json") -> int:
    import json 
    import os

    print(f"[collector] Recuperation des CVE des {days_back} derniers jours.")
    cves = get_recent_cves(days_back=days_back)


    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
 
    print(f"[collector] {len(cves)} CVE collectees et sauvegardees dans {output_path}")
    return len(cves)

if __name__ == "__main__":
    collect_and_save(days_back=7)