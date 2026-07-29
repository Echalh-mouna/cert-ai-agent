from database import get_connection, DB_PATH
from kev_checker import fetch_kev_catalog

conn = get_connection(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT cve_id FROM cve LIMIT 5")
print("Exemples d'IDs en base :", cursor.fetchall())

conn.close()

kev_ids = fetch_kev_catalog()
print("Exemples d'IDs dans KEV :", kev_ids[:5])