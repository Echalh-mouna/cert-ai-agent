"""
remediation_tracker.py

Suivi de la remédiation (Semaine 6) : chaque équipement notifié pour une CVE
passe par un cycle en_attente → corrigé, avec relance automatique si aucune
confirmation n'intervient dans le délai fixé.

Choix d'architecture (délibéré, cf. discussion) : la confirmation de
correction est déclarée manuellement (mark_as_fixed), pas détectée
automatiquement — on n'a pas d'accès réel aux machines des entreprises
fictives. Un lien cliquable dans l'email (via un petit serveur Flask) est
une évolution possible mais volontairement différée pour ne pas complexifier
prématurément le pipeline avant que la logique de suivi elle-même soit validée.

Suivi par (cve_id, equipment_id), pas par (cve_id, company) : une entreprise
peut avoir plusieurs équipements concernés par une même CVE, corrigés à des
rythmes différents.
"""

from database import get_connection, DB_PATH, get_pending_reminders, update_last_reminder, mark_as_fixed
from mail_generator import send_email

REMINDER_DAYS_THRESHOLD = 7


def confirm_fixed(cve_id: str, equipment_id: int, db_path: str = DB_PATH) -> bool:
    """
    Déclare un équipement comme corrigé pour une CVE donnée. À appeler
    manuellement pour simuler la confirmation du responsable (en attendant
    une éventuelle interface web).

    Returns:
        True si la mise à jour a bien trouvé une ligne correspondante.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    updated = mark_as_fixed(cursor, cve_id, equipment_id)
    conn.commit()
    conn.close()

    if updated:
        print(f"[remediation] {cve_id} / équipement {equipment_id} marqué comme corrigé.")
    else:
        print(f"[remediation] Aucun suivi trouvé pour {cve_id} / équipement {equipment_id} "
              f"(vérifie que l'alerte a bien été envoyée pour cet équipement).")
    return updated


def build_reminder_body(reminder: dict) -> str:
    """Construit le corps de l'email de relance."""
    return f"""Bonjour {reminder['responsible_name']},

RELANCE — Aucune confirmation de correction n'a été reçue pour l'alerte suivante :

CVE : {reminder['cve_id']}
Équipement : {reminder['company']} — {reminder['vendor']} {reminder['product']} ({reminder['version']})
Notifié initialement le : {reminder['notified_at']}

Merci de confirmer si le correctif a été appliqué, ou de nous indiquer si une
action est en cours. Sans retour, une nouvelle relance sera envoyée.

Cordialement,
CERT AI Agent (relance automatique)
"""


def send_reminders(days_threshold: int = REMINDER_DAYS_THRESHOLD, db_path: str = DB_PATH) -> int:
    """
    Fonction principale : identifie les suivis en attente depuis plus de
    days_threshold jours, envoie une relance, et met à jour l'horodatage.

    Returns:
        Le nombre de relances envoyées.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    reminders = get_pending_reminders(cursor, days_threshold)
    conn.close()

    print(f"[remediation] {len(reminders)} suivi(s) en attente depuis plus de "
          f"{days_threshold} jour(s) sans confirmation.")

    sent_count = 0
    for reminder in reminders:
        subject = f"[RELANCE CERT] {reminder['cve_id']} — correction toujours en attente"
        body = build_reminder_body(reminder)

        success = send_email(reminder["responsible_email"], subject, body)

        # On met à jour last_reminder_at même si l'envoi SMTP échoue (ex. pas
        # de réseau) : ça évite de spammer en boucle si le prochain run tourne
        # peu après ; la relance sera retentée au prochain cycle naturel.
        conn = get_connection(db_path)
        cursor = conn.cursor()
        update_last_reminder(cursor, reminder["id"])
        conn.commit()
        conn.close()

        if success:
            sent_count += 1
            print(f"[remediation] Relance envoyée : {reminder['cve_id']} → {reminder['responsible_email']}")

    print(f"[remediation] {sent_count} relance(s) envoyée(s) avec succès.")
    return sent_count


if __name__ == "__main__":
    import sys

    if "--fix" in sys.argv:
        idx = sys.argv.index("--fix")
        cve_id = sys.argv[idx + 1]
        equipment_id = int(sys.argv[idx + 2])
        confirm_fixed(cve_id, equipment_id)
    else:
        days = int(sys.argv[1]) if len(sys.argv) > 1 else REMINDER_DAYS_THRESHOLD
        send_reminders(days_threshold=days)