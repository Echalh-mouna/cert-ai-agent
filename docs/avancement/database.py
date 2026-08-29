import sqlite3

DB_PATH = "data/cert_agent.db"


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve (
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
        CREATE TABLE IF NOT EXISTS vendors (
            vendor_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
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
        CREATE TABLE IF NOT EXISTS "references" (
            reference_id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            url TEXT,
            FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
        )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_products_cve_id ON products(cve_id)"
    )

    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_references_cve_id '
        'ON "references"(cve_id)'
    )

    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_products "
        "ON products(cve_id, vendor_id, product, version)"
    )

    cursor.execute(
        'CREATE UNIQUE INDEX IF NOT EXISTS ux_references '
        'ON "references"(cve_id, url)'
    )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            source_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_sources (
            cve_id TEXT NOT NULL,
            source_id INTEGER NOT NULL,
            first_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (cve_id, source_id),
            FOREIGN KEY (cve_id) REFERENCES cve(cve_id),
            FOREIGN KEY (source_id) REFERENCES sources(source_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certfr_advisories (
            reference TEXT PRIMARY KEY,
            title TEXT,
            summary TEXT,
            risks TEXT,
            solutions TEXT,
            documentation TEXT,
            link TEXT,
            published_date TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certfr_advisory_cve (
            reference TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            PRIMARY KEY (reference, cve_id),
            FOREIGN KEY (reference) REFERENCES certfr_advisories(reference),
            FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
        )
    """)

    conn.commit()
    conn.close()

    print(f"[database] Base de données initialisée dans {db_path}")


def get_or_create_vendor(
    cursor: sqlite3.Cursor,
    vendor_name: str
) -> int:
    cursor.execute(
        "SELECT vendor_id FROM vendors WHERE name = ?",
        (vendor_name,)
    )

    row = cursor.fetchone()

    if row:
        return row[0]

    cursor.execute(
        "INSERT INTO vendors (name) VALUES (?)",
        (vendor_name,)
    )

    return cursor.lastrowid


def register_source(
    cursor: sqlite3.Cursor,
    cve_id: str,
    source_name: str
) -> None:
    cursor.execute(
        "INSERT OR IGNORE INTO sources (name) VALUES (?)",
        (source_name,)
    )

    cursor.execute(
        "SELECT source_id FROM sources WHERE name = ?",
        (source_name,)
    )

    source_id = cursor.fetchone()[0]

    cursor.execute(
        "INSERT OR IGNORE INTO cve_sources (cve_id, source_id) "
        "VALUES (?, ?)",
        (cve_id, source_id)
    )


def upsert_cve(
    cursor: sqlite3.Cursor,
    cve: dict,
    source_name: str,
    primary: bool = False
) -> None:

    cursor.execute(
        "SELECT cve_id FROM cve WHERE cve_id = ?",
        (cve["cve_id"],)
    )

    exists = cursor.fetchone() is not None

    if not exists:
        cursor.execute("""
            INSERT INTO cve (
                cve_id,
                description,
                cvss_score,
                cvss_severity,
                cvss_vector,
                published_date,
                last_modified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            cve["cve_id"],
            cve.get("description"),
            cve.get("cvss_score"),
            cve.get("cvss_severity"),
            cve.get("cvss_vector"),
            cve.get("published_date"),
            cve.get("last_modified"),
        ))

    elif primary:
        cursor.execute("""
            UPDATE cve SET
                description = ?,
                cvss_score = ?,
                cvss_severity = ?,
                cvss_vector = ?,
                published_date = ?,
                last_modified = ?
            WHERE cve_id = ?
        """, (
            cve.get("description"),
            cve.get("cvss_score"),
            cve.get("cvss_severity"),
            cve.get("cvss_vector"),
            cve.get("published_date"),
            cve.get("last_modified"),
            cve["cve_id"],
        ))

    else:
        cursor.execute("""
            UPDATE cve SET
                description = COALESCE(
                    NULLIF(?, ''),
                    description
                ),
                cvss_score = COALESCE(
                    cvss_score,
                    ?
                ),
                cvss_severity = COALESCE(
                    cvss_severity,
                    ?
                ),
                cvss_vector = COALESCE(
                    cvss_vector,
                    ?
                ),
                last_modified = COALESCE(
                    ?,
                    last_modified
                )
            WHERE cve_id = ?
        """, (
            cve.get("description"),
            cve.get("cvss_score"),
            cve.get("cvss_severity"),
            cve.get("cvss_vector"),
            cve.get("last_modified"),
            cve["cve_id"],
        ))

    for product in cve.get("affected_products", []):
        vendor_id = get_or_create_vendor(
            cursor,
            product.get("vendor", "unknown")
        )

        cursor.execute("""
            INSERT OR IGNORE INTO products (
                cve_id,
                vendor_id,
                product,
                version,
                version_start_including,
                version_end_excluding
            )
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
        cursor.execute(
            'INSERT OR IGNORE INTO "references" (cve_id, url) '
            "VALUES (?, ?)",
            (cve["cve_id"], url)
        )

    register_source(
        cursor,
        cve["cve_id"],
        source_name
    )


def upsert_certfr_advisory(
    cursor: sqlite3.Cursor,
    advisory: dict,
    cve_ids: list[str]
) -> None:

    cursor.execute("""
        INSERT INTO certfr_advisories (
            reference,
            title,
            summary,
            risks,
            solutions,
            documentation,
            link,
            published_date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(reference) DO UPDATE SET
            title = excluded.title,
            summary = excluded.summary,
            risks = excluded.risks,
            solutions = excluded.solutions,
            documentation = excluded.documentation,
            link = excluded.link,
            published_date = excluded.published_date
    """, (
        advisory["reference"],
        advisory.get("title"),
        advisory.get("summary"),
        advisory.get("risks"),
        advisory.get("solutions"),
        advisory.get("documentation"),
        advisory.get("link"),
        advisory.get("published_date"),
    ))

    for cve_id in cve_ids:
        cursor.execute(
            "INSERT OR IGNORE INTO certfr_advisory_cve "
            "(reference, cve_id) VALUES (?, ?)",
            (advisory["reference"], cve_id)
        )


def load_parsed_cves(
    input_path: str = "data/parsed_cves.json",
    db_path: str = DB_PATH
) -> int:

    import json

    init_db(db_path)

    with open(input_path, "r", encoding="utf-8") as f:
        parsed_cves = json.load(f)

    conn = get_connection(db_path)
    cursor = conn.cursor()

    count = 0

    for cve in parsed_cves:
        try:
            upsert_cve(
                cursor,
                cve,
                source_name="NVD",
                primary=True
            )
            count += 1

        except Exception as e:
            print(
                f"[database] Erreur lors de l'insertion de "
                f"{cve.get('cve_id')} : {e}"
            )

    conn.commit()
    conn.close()

    print(
        f"[database] {count} CVE insérées/mises à jour "
        f"dans la base (source NVD)."
    )

    return count


if __name__ == "__main__":
    load_parsed_cves()