import requests 
import sqlite3

from database import get_connection, DB_PATH

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev_catalog() -> list[str]:
    response = requests.get(CISA_KEV_URL, timeout=30)
    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities",[])

    return [vuln.get("cveID") for vuln in vulnerabilities if vuln.get("cveID")]

def update_exploit_status(db_path: str=DB_PATH) -> int:
    print("[kev_checker] Telechargement du catalogue CISA KEV...")

    kev_ids = fetch_kev_catalog()
    print(f"[kev_checker] {len(kev_ids)} CVE referencees dans le catalogue KEV.")

    conn = get_connection(db_path)
    cursor = conn.cursor()

    updated = 0
    for cve_id in kev_ids:
        cursor.execute("""
            UPDATE cve SET exploit_public = 1 WHERE cve_id = ?

       """ , (cve_id,))
        if cursor.rowcount > 0 :
            updated += 1

    conn.commit()
    conn.close()

    print(f"[kev_checker] {updated} CVE de la base locale marquees comme"
          f"activement exploitees (correspondance trouvee dans KEV).")
    return updated 


if __name__ == "__main__":
    update_exploit_status()