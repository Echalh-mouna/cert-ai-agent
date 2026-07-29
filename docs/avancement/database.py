import sqlite3
import json 

DB_PATH = "data/cert_agent.db"

def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path : str = DB_PATH) -> None:
    conn = get_connection(db_path)
    cursor=conn.cursor()

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS cve(
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT, 
            cvss_vector TEXT, 
            published_date TEXT,
            last_modified TEXT,
            exploit_public INTEGER DEFAULT 0,
            remediation_notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )

        """)

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS vendors(
             vendor_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        ) 
    """)


    cursor.execute("""
            CREATE TABLE IF NOT EXISTS products(

                    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    vendor_id INTEGER,
                    product TEXT,
                    version TEXT,
                    version_start_including TEXT,
                    version_end_excluding TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cve(cve_id),
                    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
            
            )
    """)


    cursor.execute("""
            CREATE TABLE IF NOT EXISTS "references"(
                reference_id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                url TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
            )

  """)

    conn.commit()
    conn.close()
    print(f"[database] base de donnees initialisee dans {db_path}")



def get_or_create_vendor(cursor:sqlite3.Cursor, vendor_name: str) -> int:
        cursor.execute("SELECT vendor_id FROM vendors WHERE name= ?",(vendor_name,))

        row = cursor.fetchone()
        if row:
            return row[0]

        cursor.execute("INSERT INTO vendors (name) VALUES (?)",(vendor_name,))
        return cursor.lastrowid



def insert_cve(cursor: sqlite3.Cursor, cve:dict)-> None:
        cursor.execute("""
            INSERT OR REPLACE INTO cve
                (cve_id,description,cvss_score,cvss_severity,cvss_vector,published_date,last_modified)

                VALUES(?, ?, ?, ?, ?, ?, ?)
            """,(
                 cve["cve_id"],
                 cve["description"],
                 cve["cvss_score"],
                 cve["cvss_severity"],
                 cve["cvss_vector"],
                 cve["published_date"],
                 cve["last_modified"],

            ))

        for product in cve.get("affected_products", []):
            vendor_id = get_or_create_vendor(cursor, product.get("vendor", "unknown"))
            cursor.execute("""
            INSERT INTO products
                (cve_id, vendor_id, product, version,
                 version_start_including, version_end_excluding)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
            cve["cve_id"],
            vendor_id,
            product.get("product"),
            product.get("version"),
            product.get("version_start_including"),
            product.get("version_end_excluding"),
        ))

        for url in cve.get("references", []):
           cursor.execute("""
            INSERT INTO "references" (cve_id, url) VALUES (?, ?)
        """, (cve["cve_id"], url))


def load_parsed_cves(input_path: str = "data/parsed_cves.json", db_path: str = DB_PATH) -> int:

    init_db(db_path)

    with open(input_path, "r", encoding="utf-8") as f:
         parsed_cves = json.load(f)

    conn = get_connection(db_path)
    cursor = conn.cursor()

    count = 0 
    for cve in parsed_cves:
         try:
              insert_cve(cursor, cve)
              count += 1
         except Exception as e:
              print(f"[database] Erreur lors de l'insertion de {cve.get('cve_id')}:{e}")

    conn.commit()
    conn.close()
 
    print(f"[database] {count} CVE insérées dans la base.")
    return count
 
 
if __name__ == "__main__":
    load_parsed_cves()
         


    
