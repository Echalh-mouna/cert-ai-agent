"""
agent.py

Agent décisionnel (Semaine 5) : orchestre les briques existantes du pipeline
en une seule logique autonome, du repérage d'une CVE critique jusqu'à la
notification des responsables concernés.

    Nouvelle CVE en base
            │
            ▼
    Critique ? (CVSS >= seuil OU exploit_public confirmé)
            │ non → ignorée (journalisée quand même, pour ne pas la
            │       ré-évaluer à chaque exécution)
            │ oui
            ▼
    matcher.py : qui est concerné ?
            │ personne → journalisée "sans impact", pas d'alerte
            │ quelqu'un
            ▼
    alert_generator.py : génération de la fiche PDF
            ▼
    VALIDATION HUMAINE (par défaut) : l'agent affiche un résumé et demande
    confirmation avant d'envoyer. --auto désactive cette étape.
            │
            ▼
    mail_generator.py : envoi (ou sauvegarde locale seule si refusé)

Ce choix (validation humaine par défaut) est délibéré : une fausse alerte
envoyée à une entreprise a un coût réel de crédibilité. L'automatisation
complète reste possible (--auto) mais n'est pas le comportement par défaut.
"""

import sys

from database import get_connection, DB_PATH, log_agent_decision, get_unprocessed_critical_cves, mark_as_notified
from matcher import match_cve_to_inventory
from alert_generator import get_cve_context, generate_alert
from mail_generator import generate_and_send_alerts

CVSS_THRESHOLD = 7.0  # seuil de criticité par défaut (HIGH et plus)


def is_critical(cve_context: dict, threshold: float = CVSS_THRESHOLD) -> bool:
    """Une CVE est jugée critique si son score CVSS dépasse le seuil, ou si
    son exploitation active est confirmée par CISA KEV (indépendamment du
    score, une exploitation confirmée justifie toujours une évaluation)."""
    score = cve_context.get("cvss_score") or 0
    return score >= threshold or bool(cve_context.get("exploit_public"))


def print_summary(cve_id: str, cve_context: dict, matches: list[dict]) -> None:
    """Affiche un résumé lisible avant de demander la validation humaine."""
    print(f"\n{'=' * 60}")
    print(f"CVE : {cve_id}")
    print(f"CVSS : {cve_context.get('cvss_score')} ({cve_context.get('cvss_severity')})")
    print(f"Exploit confirmé (KEV) : {'Oui' if cve_context.get('exploit_public') else 'Non'}")
    print(f"Équipements concernés : {len(matches)}")
    for m in matches:
        print(f"  - {m['company']} : {m['vendor']} {m['product']} ({m['version']}) "
              f"[{m['confidence']}] → {m['responsible_name']}")
    print(f"{'=' * 60}")


def ask_confirmation(cve_id: str) -> bool:
    """Demande une confirmation humaine avant l'envoi. Toute réponse autre
    qu'un 'oui' explicite est traitée comme un refus (prudence par défaut)."""
    answer = input(f"\nEnvoyer l'alerte pour {cve_id} ? [oui/non] : ").strip().lower()
    return answer in ("oui", "o", "yes", "y")


def evaluate_cve(cve_id: str, auto: bool = False, db_path: str = DB_PATH) -> str:
    """
    Évalue une CVE et déclenche (ou non) le reste du pipeline.

    Returns:
        La décision prise : "ignoree", "sans_impact", "envoyee", "refusee".
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cve_context = get_cve_context(cve_id, db_path)

    if not is_critical(cve_context):
        log_agent_decision(cursor, cve_id, "ignoree",
                            f"CVSS={cve_context.get('cvss_score')}, sous le seuil et non exploitée")
        conn.commit()
        conn.close()
        return "ignoree"

    matches = match_cve_to_inventory(cve_id, db_path)
    if not matches:
        log_agent_decision(cursor, cve_id, "sans_impact",
                            "Critique mais aucun équipement de l'inventaire concerné")
        conn.commit()
        conn.close()
        return "sans_impact"

    print_summary(cve_id, cve_context, matches)
    generate_alert(cve_id)  # génère (ou régénère) la fiche PDF avant décision d'envoi

    should_send = True if auto else ask_confirmation(cve_id)

    generate_and_send_alerts(cve_id, send=should_send, db_path=db_path)

    if should_send:
        # Démarre le suivi de remédiation pour chaque équipement notifié.
        # Réutilise la connexion déjà ouverte en haut de la fonction — ne
        # PAS en ouvrir une nouvelle ici (bug précédent : ça fermait la
        # connexion utilisée par le log_agent_decision juste après).
        for m in matches:
            mark_as_notified(cursor, cve_id, m["equipment_id"])

    decision = "envoyee" if should_send else "refusee"
    log_agent_decision(cursor, cve_id, decision,
                        f"{len(matches)} équipement(s) concerné(s), mode {'auto' if auto else 'manuel'}")
    conn.commit()
    conn.close()
    return decision


def run_agent(auto: bool = False, cvss_threshold: float = CVSS_THRESHOLD, db_path: str = DB_PATH) -> None:
    """
    Point d'entrée principal : parcourt toutes les CVE critiques non encore
    évaluées par l'agent, et applique la logique décisionnelle sur chacune.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cve_ids = get_unprocessed_critical_cves(cursor, cvss_threshold)
    conn.close()

    print(f"[agent] {len(cve_ids)} CVE critique(s) non encore évaluée(s) (seuil CVSS >= {cvss_threshold}).")

    summary = {"ignoree": 0, "sans_impact": 0, "envoyee": 0, "refusee": 0}
    for cve_id in cve_ids:
        try:
            decision = evaluate_cve(cve_id, auto=auto, db_path=db_path)
            summary[decision] += 1
        except Exception as e:
            print(f"[agent] Erreur lors de l'évaluation de {cve_id} : {e}")

    print(f"\n[agent] Bilan : {summary}")


if __name__ == "__main__":
    auto_mode = "--auto" in sys.argv

    # Usage ciblé sur une seule CVE : python agent.py CVE-2026-15409 [--auto]
    cve_arg = next((a for a in sys.argv[1:] if a.startswith("CVE-")), None)

    if cve_arg:
        result = evaluate_cve(cve_arg, auto=auto_mode)
        print(f"\n[agent] Décision pour {cve_arg} : {result}")
    else:
        run_agent(auto=auto_mode)