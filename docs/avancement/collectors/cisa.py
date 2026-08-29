"""
collectors/cisa.py

Connecteur pour CISA Cybersecurity Advisories (source SECONDAIRE, même
principe que collectors/certfr.py : ne fait pas autorité sur les champs
communs de la CVE, complète seulement ce qui est vide, ne touche jamais
published_date sur une CVE déjà existante).

⚠️ AVERTISSEMENT — encore plus important ici que pour CERT-FR :
Contrairement à CERT-FR (qui expose un champ JSON structuré "cves": [...]),
CISA Advisories ne semble pas offrir cette même API riche par avis à ma
connaissance. Ce module part donc sur l'hypothèse la plus simple : parser
le flux RSS des avis, et extraire les identifiants CVE par regex depuis le
titre/la description. C'EST UNE HYPOTHÈSE NON VÉRIFIÉE.

Ne lance JAMAIS collect_cisa() directement sans être passé par
`python -m collectors.cisa --debug` d'abord, exactement comme pour CERT-FR
où le --debug a permis de découvrir un format complètement différent de ce
qui avait été anticipé au départ.

URL du flux à vérifier en premier : la page des advisories CISA a plusieurs
flux possibles selon la catégorie (ICS, généraliste). Le --debug affiche le
contenu brut du premier item pour te permettre de confirmer la bonne URL et
la présence/absence de CVE dans le texte.
"""

import re
import requests
import xml.etree.ElementTree as ET

from database import get_connection, DB_PATH, upsert_cve, upsert_cisa_advisory

# À CONFIRMER : CISA publie plusieurs flux selon la catégorie d'avis
# (advisories généralistes vs ICS). Celui-ci cible les advisories
# généralistes ; si le --debug ne remonte rien d'exploitable, essayer
# la variante ICS : https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml
CISA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
USER_AGENT = "cert-ai-agent/1.0"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def fetch_cisa_rss(feed_url: str = CISA_RSS_URL) -> list[dict]:
    """Récupère et parse le flux RSS des advisories CISA."""
    response = requests.get(feed_url, timeout=20, headers={"User-Agent": USER_AGENT})
    response.raise_for_status()

    root = ET.fromstring(response.content)
    items = []

    for item in root.findall(".//item"):
        title = item.findtext("title", default="")
        link = item.findtext("link", default="")
        description = item.findtext("description", default="")
        pub_date = item.findtext("pubDate", default="")

        # La référence CISA est généralement le dernier segment du lien
        # (ex. "aa26-233a" ou "icsa-26-123-01") — À CONFIRMER via --debug.
        reference = link.rstrip("/").split("/")[-1] if link else ""

        items.append({
            "title": title, "link": link, "description": description,
            "pub_date": pub_date, "reference": reference,
        })

    return items


def extract_cve_ids(text: str) -> list[str]:
    """
    Extraction par regex depuis texte libre (titre + description).
    Moins fiable qu'un champ structuré (voir avertissement en tête de
    fichier) : si le --debug révèle un champ CVE structuré quelque part
    (ex. en allant chercher la page HTML de l'avis), remplacer cette
    fonction par une extraction directe comme on l'a fait pour CERT-FR.
    """
    return list(set(CVE_PATTERN.findall(text or "")))


def normalize_cve_entry(cve_id: str, rss_item: dict) -> dict:
    """Construit l'entrée CVE au format commun (compatible upsert_cve).
    Comme pour CERT-FR : pas de CVSS, pas de description générale, pas de
    date de publication (NVD reste la référence sur ces champs)."""
    return {
        "cve_id": cve_id,
        "description": None,
        "cvss_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
        "published_date": None,
        "last_modified": None,
        "affected_products": [],   # pas de source structurée identifiée pour l'instant
        "references": [rss_item["link"]] if rss_item["link"] else [],
    }


def debug_print_raw_item(feed_url: str = CISA_RSS_URL) -> None:
    """
    Affiche le premier item RSS brut ET indique si des CVE ont pu être
    extraites par regex dessus. À lancer en PREMIER, avant tout traitement
    réel — c'est ce qui a permis de corriger complètement les hypothèses
    initiales sur CERT-FR, ce sera probablement pareil ici.
    """
    items = fetch_cisa_rss(feed_url)
    if not items:
        print(f"[cisa] Aucun item trouvé sur {feed_url}. "
              f"Essaie peut-être l'URL alternative ICS en argument.")
        return

    print(f"[cisa] {len(items)} items récupérés. Premier item brut :")
    print(items[0])

    cve_ids = extract_cve_ids(items[0]["title"] + " " + items[0]["description"])
    print(f"\n[cisa] CVE détectées par regex sur cet item : {cve_ids or '(aucune)'}")
    if not cve_ids:
        print("[cisa] ATTENTION : aucune CVE détectée sur le premier item. "
              "Vérifie manuellement dans un navigateur si cet avis mentionne bien "
              "des CVE, et si oui, sous quel format (peut-être faut-il aller "
              "chercher la page complète de l'avis, pas juste le résumé RSS).")


def collect_cisa(limit: int = 20, db_path: str = DB_PATH) -> int:
    """
    Collecte les derniers avis CISA, extrait les CVE mentionnées (par regex,
    voir avertissement), et les insère en base (fusion multi-source, comme
    pour CERT-FR : upsert_cve d'abord, puis le lien avis→CVE).

    Returns:
        Le nombre de CVE DISTINCTES traitées sur ce run.
    """
    print("[cisa] Récupération du flux RSS CISA...")
    items = fetch_cisa_rss()[:limit]
    print(f"[cisa] {len(items)} avis récupérés.")

    conn = get_connection(db_path)
    cursor = conn.cursor()

    seen_cve_ids = set()

    for item in items:
        cve_ids = extract_cve_ids(item["title"] + " " + item["description"])
        if not cve_ids:
            continue  # avis sans CVE détectée dans le texte disponible

        # Ordre important (leçon tirée du bug CERT-FR) : créer les CVE
        # d'abord, lier l'avis ensuite, sinon violation de contrainte FK.
        for cve_id in cve_ids:
            entry = normalize_cve_entry(cve_id, item)
            try:
                upsert_cve(cursor, entry, source_name="CISA", primary=False)
                seen_cve_ids.add(cve_id)
            except Exception as e:
                print(f"[cisa] Erreur lors de l'insertion de {cve_id} : {e}")

        advisory = {
            "reference": item["reference"] or item["link"],
            "title": item["title"],
            "summary": item["description"],
            "link": item["link"],
            "published_date": item["pub_date"],
        }
        try:
            upsert_cisa_advisory(cursor, advisory, cve_ids)
        except Exception as e:
            print(f"[cisa] Erreur lors de l'enregistrement de l'avis {item['reference']} : {e}")

    conn.commit()
    conn.close()

    print(f"[cisa] {len(seen_cve_ids)} CVE distinctes traitées depuis CISA.")
    return len(seen_cve_ids)


if __name__ == "__main__":
    import sys

    # CISA a supprimé son flux RSS généraliste (all.xml) en mai 2025, sans
    # remplacement officiel. On teste ici les flux spécialisés ICS, qui
    # pourraient avoir survécu (à confirmer) :
    #   python -m collectors.cisa --debug --ics
    #   python -m collectors.cisa --debug --ics-medical
    if "--ics-medical" in sys.argv:
        test_url = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"
    elif "--ics" in sys.argv:
        test_url = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
    else:
        test_url = CISA_RSS_URL

    if "--debug" in sys.argv:
        debug_print_raw_item(test_url)
    else:
        collect_cisa()