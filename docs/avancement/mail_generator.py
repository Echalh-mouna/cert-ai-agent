import os
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from collections import defaultdict

from dotenv import load_dotenv

from matcher import match_cve_to_inventory
from database import get_connection, DB_PATH
from alert_generator import generate_alert

load_dotenv()
_original_getaddrinfo = socket.getaddrinfo
def _getaddrinfo_ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
    return _original_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _getaddrinfo_ipv4_only

EMAILS_DIR = "emails"
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("CERT_SMTP_USER", "")      
SMTP_PASSWORD = os.environ.get("CERT_SMTP_PASSWORD", "") 


def get_cve_summary(cve_id: str, db_path: str = DB_PATH) -> dict:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cvss_score, cvss_severity FROM cve WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    conn.close()
    return {"cvss_score": row[0], "cvss_severity": row[1]} if row else {}


def group_matches_by_responsible(matches: list[dict]) -> dict:
    grouped = defaultdict(list)
    for m in matches:
        key = (m["responsible_name"], m["responsible_email"])
        grouped[key].append(m)
    return grouped


def build_email_body(cve_id: str, cve_summary: dict, equipments: list[dict], name: str) -> str:
    equipment_lines = "\n".join(
        f"  - {e['company']} : {e['vendor']} {e['product']} (version {e['version']}) "
        f"[confiance du matching : {e['confidence']}]"
        for e in equipments
    )

    return f"""Bonjour {name},

Une nouvelle vulnérabilité critique a été identifiée et concerne un ou plusieurs
équipements dont vous êtes responsable :

CVE : {cve_id}
Score CVSS : {cve_summary.get('cvss_score', 'N/A')} ({cve_summary.get('cvss_severity', 'N/A')})

Équipement(s) concerné(s) :
{equipment_lines}

Vous trouverez la fiche d'alerte complète (analyse de risque, exploitabilité,
remédiation détaillée) en pièce jointe de cet email.

Merci de prendre connaissance de la fiche d'alerte et de planifier la remédiation
dans les meilleurs délais. Une relance automatique sera envoyée si aucune action
n'est constatée.

Cordialement,
CERT AI Agent (notification automatique)
"""


def send_email(to_email: str, subject: str, body: str, attachment_path: str = "") -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        print("[mail_generator] CERT_SMTP_USER / CERT_SMTP_PASSWORD non configurés — "
              "email non envoyé, seulement sauvegardé localement.")
        return False

    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, "rb") as f:
            attachment = MIMEApplication(f.read(), _subtype="pdf")
        attachment.add_header("Content-Disposition", "attachment",
                               filename=os.path.basename(attachment_path))
        msg.attach(attachment)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"[mail_generator] Email envoyé à {to_email}")
        return True
    except Exception as e:
        print(f"[mail_generator] Échec de l'envoi via port 587 (STARTTLS) : {e}")
        print("[mail_generator] Tentative via port 465 (SSL direct)...")
        try:
            with smtplib.SMTP_SSL(SMTP_HOST, 465) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
            print(f"[mail_generator] Email envoyé à {to_email} (via port 465)")
            return True
        except Exception as e2:
            print(f"[mail_generator] Échec également via port 465 : {e2}")
            print("[mail_generator] Le réseau actuel bloque probablement les connexions SMTP sortantes.")
            return False


def generate_and_send_alerts(cve_id: str, send: bool = False, db_path: str = DB_PATH) -> int:
    matches = match_cve_to_inventory(cve_id, db_path)
    if not matches:
        print(f"[mail_generator] {cve_id} : aucun équipement concerné, aucun email à générer.")
        return 0

    cve_summary = get_cve_summary(cve_id, db_path)
    grouped = group_matches_by_responsible(matches)
    expected_pdf_path = os.path.join("alerts", f"{cve_id}.pdf")
    if os.path.exists(expected_pdf_path):
        print(f"[mail_generator] Fiche déjà générée trouvée : {expected_pdf_path} (pas de régénération)")
        pdf_path = expected_pdf_path
    else:
        print(f"[mail_generator] Aucune fiche existante pour {cve_id} — génération nécessaire...")
        pdf_path = generate_alert(cve_id)

    os.makedirs(EMAILS_DIR, exist_ok=True)
    count = 0

    for (name, email), equipments in grouped.items():
        subject = f"[ALERTE CERT] {cve_id} — action requise ({cve_summary.get('cvss_severity', 'N/A')})"
        body = build_email_body(cve_id, cve_summary, equipments, name)
        safe_name = name.replace(" ", "_")
        output_path = os.path.join(EMAILS_DIR, f"{cve_id}_{safe_name}.txt")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"À : {email}\nObjet : {subject}\nPièce jointe : {pdf_path or 'aucune'}\n\n{body}")
        print(f"[mail_generator] Email préparé pour {name} <{email}> → {output_path}")

        if send:
            send_email(email, subject, body, attachment_path=pdf_path)

        count += 1

    return count


if __name__ == "__main__":
    import sys

    cve_id = sys.argv[1] if len(sys.argv) > 1 else None
    if not cve_id:
        print("Usage : python mail_generator.py CVE-2025-12345 [--send]")
        sys.exit(1)

    should_send = "--send" in sys.argv
    generate_and_send_alerts(cve_id, send=should_send)