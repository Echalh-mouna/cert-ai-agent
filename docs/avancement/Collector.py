import requests
import time
from datetime import datetime, timedelta, timezone

NVD_API_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_recent_cves(days_back: int =7, results_per_page: int = 2000) -> list[dict]:
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days = days_back)
    all_vulnerabilities =[]
    start_index = 0

    while True:
        params = {
            "pubStartDate" : start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate" : end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage":results_per_page,
            "startIndex": start_index,
        }

        response = requests.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities",[])
        total_results = data.get("totalResults",0)

        all_vulnerabilities.extend(vulnerabilities)
        print(f"[collector] Page récupérée : {len(all_vulnerabilities)}/{total_results} CVE")

        start_index += results_per_page


        if start_index >= total_results or not vulnerabilities:
            break 

        time.sleep(6)

    return all_vulnerabilities

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
    import sys

    days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    collect_and_save(days_back=days)