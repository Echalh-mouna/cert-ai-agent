"""
database.py (v2)

Corrections apportées suite à la revue de code sur le passage multi-source :

1. insert_cve() n'utilise plus INSERT OR REPLACE. Ce mécanisme fait un
   DELETE puis un INSERT en interne ; or avec les contraintes de clé
   étrangère actives (PRAGMA foreign_keys = ON) et des tables enfants
   (products, "references", cve_sources) qui référencent cve.cve_id, ce
   DELETE échoue dès qu'une ligne enfant existe déjà — donc dès qu'on
   relance collector.py sur une CVE déjà en base. Remplacé par un vrai
   UPSERT SQLite (INSERT ... ON CONFLICT DO UPDATE), qui met à jour en
   place sans jamais supprimer la ligne.

2. insert_cve() et upsert_cve_multisource() sont fusionnées en une seule
   fonction upsert_cve(cursor, cve, source_name, primary=False) :
   - primary=True (NVD) : écrase les champs communs (NVD fait autorité)
   - primary=False (CERT-FR, CISA...) : ne fait que compléter les champs
     vides (COALESCE), et ne touche JAMAIS published_date sur une CVE
     déjà existante (NVD reste la référence pour cette date)
   - products/references : toujours INSERT OR IGNORE (jamais de DELETE),
     pour ne pas perdre les produits/références apportés par une autre
     source lors d'un rechargement

3. Ajout des tables certfr_advisories / certfr_advisory_cve : les données
   propres à un avis CERT-FR (résumé, risques, solutions, documentation)
   ne sont PAS mélangées dans la table cve (qui reste les données
   communes de la vulnérabilité) — elles ont leur propre stockage, relié
   aux CVE via une table de jonction (un avis peut couvrir plusieurs CVE).
"""

import sqlite3

DB_PATH = "data/cert_agent.db"


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Ouvre (ou crée) la connexion à la base SQLite."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    """Crée toutes les tables si elles n'existent pas encore."""
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

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_cve_id ON products(cve_id)")
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_references_cve_id ON "references"(cve_id)')
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_products "
                    "ON products(cve_id, vendor_id, product, version)")
    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS ux_references '
                    'ON "references"(cve_id, url)')

    # --- Traçabilité multi-source ---
    # Une CVE peut être vue par plusieurs sources CTI. On ne met jamais un
    # champ "source" unique dans cve : chaque (cve_id, source) est tracé
    # séparément, avec la date de première observation par cette source.
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

    # --- Données propres aux avis CERT-FR (résumé, risques, solutions...) ---
    # Séparées de cve : ce sont des informations propres à l'AVIS, pas à la
    # vulnérabilité elle-même (deux avis différents peuvent traiter la même
    # CVE avec des recommandations différentes selon le contexte français).
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

    # --- Données propres aux avis CISA (mêmes principes que CERT-FR) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cisa_advisories (
            reference TEXT PRIMARY KEY,
            title TEXT,
            summary TEXT,
            link TEXT,
            published_date TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cisa_advisory_cve (
            reference TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            PRIMARY KEY (reference, cve_id),
            FOREIGN KEY (reference) REFERENCES cisa_advisories(reference),
            FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
        )
    """)

    # --- Journal des décisions de l'agent (Semaine 5) ---
    # Évite de retraiter/renotifier une CVE déjà évaluée à chaque exécution.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_log (
            cve_id TEXT PRIMARY KEY,
            decision TEXT NOT NULL,
            details TEXT,
            processed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
        )
    """)

    # --- Suivi de la remédiation (Semaine 6) ---
    # Suivi par (cve_id, equipment_id) et non (cve_id, company) : une même
    # entreprise peut avoir plusieurs équipements concernés par une CVE,
    # corrigés à des rythmes différents.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            equipment_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'en_attente',
            notified_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_reminder_at TEXT,
            fixed_at TEXT,
            UNIQUE(cve_id, equipment_id),
            FOREIGN KEY (cve_id) REFERENCES cve(cve_id),
            FOREIGN KEY (equipment_id) REFERENCES equipment(equipment_id)
        )
    """)

    conn.commit()
    conn.close()
    print(f"[database] Base de données initialisée dans {db_path}")


def get_or_create_vendor(cursor: sqlite3.Cursor, vendor_name: str) -> int:
    """Retourne l'ID d'un vendor existant, ou le crée s'il n'existe pas."""
    cursor.execute("SELECT vendor_id FROM vendors WHERE name = ?", (vendor_name,))
    row = cursor.fetchone()
    if row:
        return row[0]
    cursor.execute("INSERT INTO vendors (name) VALUES (?)", (vendor_name,))
    return cursor.lastrowid


def register_source(cursor: sqlite3.Cursor, cve_id: str, source_name: str) -> None:
    """Enregistre qu'une CVE a été vue par une source donnée (idempotent)."""
    cursor.execute("INSERT OR IGNORE INTO sources (name) VALUES (?)", (source_name,))
    cursor.execute("SELECT source_id FROM sources WHERE name = ?", (source_name,))
    source_id = cursor.fetchone()[0]
    cursor.execute(
        "INSERT OR IGNORE INTO cve_sources (cve_id, source_id) VALUES (?, ?)",
        (cve_id, source_id),
    )


def upsert_cve(cursor: sqlite3.Cursor, cve: dict, source_name: str, primary: bool = False) -> None:
    """
    Point d'entrée UNIQUE pour insérer/mettre à jour une CVE, quelle que
    soit la source. Remplace les anciennes insert_cve() / upsert_cve_multisource()
    séparées.

    Args:
        primary: True pour une source qui fait autorité sur les champs
                 communs (NVD) — écrase description/CVSS/dates.
                 False pour une source secondaire (CERT-FR, CISA...) — ne
                 complète que les champs vides, ne touche jamais
                 published_date sur une CVE déjà existante.
    """
    cursor.execute("SELECT cve_id FROM cve WHERE cve_id = ?", (cve["cve_id"],))
    exists = cursor.fetchone() is not None

    if not exists:
        # Nouvelle CVE : peu importe la source, on insère ce qu'on a.
        cursor.execute("""
            INSERT INTO cve (cve_id, description, cvss_score, cvss_severity,
                              cvss_vector, published_date, last_modified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            cve["cve_id"], cve.get("description"), cve.get("cvss_score"),
            cve.get("cvss_severity"), cve.get("cvss_vector"),
            cve.get("published_date"), cve.get("last_modified"),
        ))
    elif primary:
        # NVD fait autorité : on écrase les champs communs sans condition.
        cursor.execute("""
            UPDATE cve SET
                description = ?, cvss_score = ?, cvss_severity = ?,
                cvss_vector = ?, published_date = ?, last_modified = ?
            WHERE cve_id = ?
        """, (
            cve.get("description"), cve.get("cvss_score"), cve.get("cvss_severity"),
            cve.get("cvss_vector"), cve.get("published_date"),
            cve.get("last_modified"), cve["cve_id"],
        ))
    else:
        # Source secondaire : complète seulement ce qui est vide, et ne
        # touche JAMAIS published_date (NVD reste la référence pour cette date).
        cursor.execute("""
            UPDATE cve SET
                description = COALESCE(NULLIF(?, ''), description),
                cvss_score = COALESCE(cvss_score, ?),
                cvss_severity = COALESCE(cvss_severity, ?),
                cvss_vector = COALESCE(cvss_vector, ?),
                last_modified = COALESCE(?, last_modified)
            WHERE cve_id = ?
        """, (
            cve.get("description"), cve.get("cvss_score"),
            cve.get("cvss_severity"), cve.get("cvss_vector"),
            cve.get("last_modified"), cve["cve_id"],
        ))

    # Produits/références : toujours ajoutés sans jamais supprimer ceux
    # déjà présents (apportés potentiellement par une autre source).
    for product in cve.get("affected_products", []):
        vendor_id = get_or_create_vendor(cursor, product.get("vendor", "unknown"))
        cursor.execute("""
            INSERT OR IGNORE INTO products
                (cve_id, vendor_id, product, version,
                 version_start_including, version_end_excluding)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cve["cve_id"], vendor_id, product.get("product"), product.get("version"),
            product.get("version_start_including"), product.get("version_end_excluding"),
        ))

    for url in cve.get("references", []):
        cursor.execute(
            'INSERT OR IGNORE INTO "references" (cve_id, url) VALUES (?, ?)',
            (cve["cve_id"], url),
        )

    register_source(cursor, cve["cve_id"], source_name)


def upsert_certfr_advisory(cursor: sqlite3.Cursor, advisory: dict, cve_ids: list[str]) -> None:
    """
    Insère/met à jour un avis CERT-FR (résumé, risques, solutions...) et le
    relie à chacune des CVE qu'il couvre. N'écrit jamais dans la table cve.
    """
    cursor.execute("""
        INSERT INTO certfr_advisories
            (reference, title, summary, risks, solutions, documentation, link, published_date)
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
        advisory["reference"], advisory.get("title"), advisory.get("summary"),
        advisory.get("risks"), advisory.get("solutions"), advisory.get("documentation"),
        advisory.get("link"), advisory.get("published_date"),
    ))

    for cve_id in cve_ids:
        cursor.execute(
            "INSERT OR IGNORE INTO certfr_advisory_cve (reference, cve_id) VALUES (?, ?)",
            (advisory["reference"], cve_id),
        )


def upsert_cisa_advisory(cursor: sqlite3.Cursor, advisory: dict, cve_ids: list[str]) -> None:
    """Insère/met à jour un avis CISA et le relie aux CVE qu'il couvre.
    N'écrit jamais dans la table cve (même principe que upsert_certfr_advisory)."""
    cursor.execute("""
        INSERT INTO cisa_advisories (reference, title, summary, link, published_date)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(reference) DO UPDATE SET
            title = excluded.title,
            summary = excluded.summary,
            link = excluded.link,
            published_date = excluded.published_date
    """, (
        advisory["reference"], advisory.get("title"), advisory.get("summary"),
        advisory.get("link"), advisory.get("published_date"),
    ))

    for cve_id in cve_ids:
        cursor.execute(
            "INSERT OR IGNORE INTO cisa_advisory_cve (reference, cve_id) VALUES (?, ?)",
            (advisory["reference"], cve_id),
        )


def log_agent_decision(cursor: sqlite3.Cursor, cve_id: str, decision: str, details: str = "") -> None:
    """Journalise la décision de l'agent pour une CVE (idempotent : la ligne
    est mise à jour si la CVE est ré-évaluée, ex. lors d'un test manuel)."""
    cursor.execute("""
        INSERT INTO agent_log (cve_id, decision, details, processed_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(cve_id) DO UPDATE SET
            decision = excluded.decision,
            details = excluded.details,
            processed_at = excluded.processed_at
    """, (cve_id, decision, details))


def mark_as_notified(cursor: sqlite3.Cursor, cve_id: str, equipment_id: int) -> None:
    """Enregistre qu'une alerte a été envoyée pour cet équipement (statut
    initial 'en_attente'). Idempotent : n'écrase pas notified_at si déjà
    enregistré (évite de repartir à zéro le délai de relance)."""
    cursor.execute("""
        INSERT OR IGNORE INTO remediation_status (cve_id, equipment_id, status, notified_at)
        VALUES (?, ?, 'en_attente', CURRENT_TIMESTAMP)
    """, (cve_id, equipment_id))


def mark_as_fixed(cursor: sqlite3.Cursor, cve_id: str, equipment_id: int) -> bool:
    """Marque un équipement comme corrigé pour une CVE donnée.
    Returns: True si une ligne a bien été mise à jour, False sinon."""
    cursor.execute("""
        UPDATE remediation_status
        SET status = 'corrige', fixed_at = CURRENT_TIMESTAMP
        WHERE cve_id = ? AND equipment_id = ?
    """, (cve_id, equipment_id))
    return cursor.rowcount > 0


def get_pending_reminders(cursor: sqlite3.Cursor, days_threshold: int = 7) -> list[dict]:
    """
    Retourne les suivis 'en_attente' dont la dernière notification (ou
    relance) remonte à plus de days_threshold jours — donc dus pour une
    nouvelle relance.
    """
    cursor.execute("""
        SELECT rs.id, rs.cve_id, rs.equipment_id, rs.notified_at, rs.last_reminder_at,
               e.company, e.vendor, e.product, e.version,
               e.responsible_name, e.responsible_email
        FROM remediation_status rs
        JOIN equipment e ON rs.equipment_id = e.equipment_id
        WHERE rs.status = 'en_attente'
          AND julianday('now') - julianday(COALESCE(rs.last_reminder_at, rs.notified_at)) >= ?
    """, (days_threshold,))
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def update_last_reminder(cursor: sqlite3.Cursor, remediation_id: int) -> None:
    """Met à jour l'horodatage de dernière relance après envoi effectif."""
    cursor.execute(
        "UPDATE remediation_status SET last_reminder_at = CURRENT_TIMESTAMP WHERE id = ?",
        (remediation_id,),
    )


def get_unprocessed_critical_cves(cursor: sqlite3.Cursor, cvss_threshold: float = 7.0) -> list[str]:
    """
    Retourne les CVE critiques (score CVSS élevé OU exploit confirmé par KEV)
    qui n'ont pas encore été évaluées par l'agent (absentes de agent_log).
    """
    cursor.execute("""
        SELECT c.cve_id FROM cve c
        LEFT JOIN agent_log a ON c.cve_id = a.cve_id
        WHERE a.cve_id IS NULL
          AND (c.cvss_score >= ? OR c.exploit_public = 1)
    """, (cvss_threshold,))
    return [row[0] for row in cursor.fetchall()]


def load_parsed_cves(input_path: str = "data/parsed_cves.json", db_path: str = DB_PATH) -> int:
    """Charge les CVE issues de parser.py (source NVD, primaire) dans la base."""
    import json

    init_db(db_path)

    with open(input_path, "r", encoding="utf-8") as f:
        parsed_cves = json.load(f)

    conn = get_connection(db_path)
    cursor = conn.cursor()

    count = 0
    for cve in parsed_cves:
        try:
            upsert_cve(cursor, cve, source_name="NVD", primary=True)
            count += 1
        except Exception as e:
            print(f"[database] Erreur lors de l'insertion de {cve.get('cve_id')} : {e}")

    conn.commit()
    conn.close()

    print(f"[database] {count} CVE insérées/mises à jour dans la base (source NVD).")
    return count


if __name__ == "__main__":
    load_parsed_cves()