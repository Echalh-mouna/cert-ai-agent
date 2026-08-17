

import sqlite3

from database import get_connection, DB_PATH



FICTIVE_EQUIPMENT = [
    {
        "company": "Entreprise A",
        "vendor": "sonicwall",
        "product": "sma6210_firmware",
        "version": "12.4.3-03245",
        "responsible_name": "Echalh Mouna",
        "responsible_email": "echalhmouna27@gmail.com"
    },
    {
        "company": "Entreprise A",
        "vendor": "microsoft",
        "product": "windows_server",
        "version": "2022",
        "responsible_name": "Echalh Mouna",
        "responsible_email": "echalhmouna27@gmail.com"
    },
    {
        "company": "Entreprise B",
        "vendor": "sonicwall",
        "product": "sma7210_firmware",
        "version": "12.5.0-02624",
        "responsible_name": "EL hany Marwa",
        "responsible_email": "echalhmouna27@gmail.com"
    },
    {
        "company": "Entreprise B",
        "vendor": "fortinet",
        "product": "fortigate_firmware",
        "version": "7.2.5",
        "responsible_name": "EL hany Marwa",
        "responsible_email": "echalhmouna27@gmail.com"
    },
    {
        "company": "Entreprise C",
        "vendor": "dbitnet",
        "product": "dbit_n300_t1_pro_firmware",
        "version": "1.0.0",
        "responsible_name": "Amrani Mohamed",
        "responsible_email": "echalhmouna27@gmail.com"
    },
    {
        "company": "Entreprise C",
        "vendor": "linux",
        "product": "ubuntu",
        "version": "22.04",
        "responsible_name": "Amrani Mohamed",
        "responsible_email": "echalhmouna27@gmail.com"
    },
    {
        "company": "Entreprise D",
        "vendor": "cisco",
        "product": "ios_xe",
        "version": "17.9.1",
        "responsible_name": "Nadia Chraibi",
        "responsible_email": "echalhmouna27@gmail.com"
    }
]


def init_inventory_table(db_path: str = DB_PATH) -> None:
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS equipment (
            equipment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT,
            responsible_name TEXT,
            responsible_email TEXT
        )
    """)

    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_equipment_vendor_product ON equipment(vendor, product)")

    conn.commit()
    conn.close()
    print(f"[inventory] Table equipment initialisée dans {db_path}")


def load_fictive_inventory(db_path: str = DB_PATH, equipment_list: list[dict] = None) -> int:
    
    init_inventory_table(db_path)

    equipment_list = equipment_list or FICTIVE_EQUIPMENT

    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM equipment")  # repart propre à chaque rechargement

    for eq in equipment_list:
        cursor.execute("""
            INSERT INTO equipment
                (company, vendor, product, version, responsible_name, responsible_email)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            eq["company"], eq["vendor"], eq["product"], eq["version"],
            eq["responsible_name"], eq["responsible_email"],
        ))

    conn.commit()
    conn.close()

    print(f"[inventory] {len(equipment_list)} équipements chargés dans la base.")
    return len(equipment_list)


def list_inventory(db_path: str = DB_PATH) -> list[dict]:
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM equipment ORDER BY company")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    for row in rows:
        print(f"  {row['company']:15} | {row['vendor']:12} | {row['product']:28} | "
              f"{row['version']:15} | {row['responsible_name']}")

    return rows


if __name__ == "__main__":
    load_fictive_inventory()
    print("\n--- Inventaire actuel ---")
    list_inventory()