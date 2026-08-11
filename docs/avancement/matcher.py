import sqlite3
from database import get_connection, DB_PATH

def get_cve_affected_products(cve_id: str, db_path: str = DB_PATH) -> list[dict]:
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.product, p.version, v.name AS vendor
        FROM products p
        LEFT JOIN vendors v ON p.vendor_id = v.vendor_id
        WHERE p.cve_id = ? 
    """,(cve_id,))

    products = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return products

def get_inventory(db_path: str = DB_PATH) -> list[dict]:
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM equipment")
    equipment = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return equipment

def _normalize(value: str) -> str:
    return (value or "").strip().lower()

def match_cve_to_inventory(cve_id: str, db_path: str = DB_PATH) ->list[dict]:
    affected_products = get_cve_affected_products(cve_id, db_path)
    inventory = get_inventory(db_path)
    matches = []

    for eq in inventory:
        for product in affected_products:
            vendor_match = _normalize(eq["vendor"]) == _normalize(product["vendor"])
            product_match = _normalize(eq["product"]) == _normalize(product["product"])

            if not (vendor_match and product_match):
                continue

            eq_version = _normalize(eq["version"])
            cve_version = _normalize(product["version"])

            if eq_version and cve_version:
                if eq_version == cve_version:
                    confidence = " confirmé"

                elif eq_version in cve_version or cve_version in eq_version:
                    confidence = "probable"
                else:
                    continue
            else:
                confidence = "à vérifier"

            matches.append({
                **eq,
                "matched_cve_product" : product["product"],
                "matched_cve_version" : product["version"],
                "confidence" : confidence,
            })
    return matches

def print_match_report(cve_id: str, db_path:str = DB_PATH) -> None:
    matches = match_cve_to_inventory(cve_id, db_path)

    if not matches:
        print(f"[matcher] {cve_id} : aucun équipement de l'inventaire n'est concerné.")
        return

    print(f"[matcher] {cve_id} : {len(matches)} équipement(s) potentiellement concerné(s) :\n")
    for m in matches:
        print(f"  - {m['company']} | {m['vendor']} {m['product']} ({m['version']}) "
              f"| Responsable : {m['responsible_name']} <{m['responsible_email']}> "
              f"| Confiance : {m['confidence']}")


if __name__ == "__main__":
    import sys
 
    cve_id = sys.argv[1] if len(sys.argv) > 1 else None
    if not cve_id:
        print("Usage : python matcher.py CVE-2025-12345")
        sys.exit(1)
 
    print_match_report(cve_id)