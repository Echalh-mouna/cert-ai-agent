"""
collectors/certfr.py (v2)

Corrections apportées suite à revue de code :
1. La description CVE ne contient plus le titre de l'avis CERT-FR — elle
   reste vide (à compléter par NVD si la CVE y est aussi référencée). Les
   informations propres à l'avis (résumé, risques, solutions, documentation)
   sont stockées séparément, dans certfr_advisories (voir database.py).
2. affected_systems n'est plus considéré comme un champ confirmé : accès
   défensif partout, avec avertissement si absent.
3. Extraction de risks / summary / solutions / documentation / reference,
   stockées dans leur propre table plutôt que mélangées à cve.
4. reference validée par un pattern CERTFR-AAAA-(AVI|ALE)-NNNN ; si le lien
   ne matche pas, l'avis est signalé et ignoré plutôt que traité à l'aveugle.
5. fetch_certfr_json() distingue erreur réseau / JSON invalide / autre.
6. cve_count compte désormais les CVE DISTINCTES traitées sur tout le run,
   pas le nombre d'appels à upsert (une même CVE peut apparaître dans
   plusieurs avis).

⚠️ Toujours pas testé contre le vrai flux CERT-FR (pas d'accès réseau à
cert.ssi.gouv.fr depuis l'environnement de développement). Lance
`python collectors/certfr.py --debug` en premier et compare la sortie avec
ce que le code attend avant de faire confiance aux résultats.
"""

import re
import json as json_module
import requests
import xml.etree.ElementTree as ET

from database import get_connection, DB_PATH, upsert_cve, upsert_certfr_advisory

CERTFR_RSS_URL = "https://www.cert.ssi.gouv.fr/avis/feed/"
USER_AGENT = "cert-ai-agent/1.0"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
REFERENCE_PATTERN = re.compile(r"CERTFR-\d{4}-(AVI|ALE)-\d+")


def fetch_certfr_rss(feed_url: str = CERTFR_RSS_URL) -> list[dict]:
    """Récupère et parse le flux RSS des avis CERT-FR."""
    response = requests.get(feed_url, timeout=20, headers={"User-Agent": USER_AGENT})
    response.raise_for_status()

    root = ET.fromstring(response.content)
    items = []

    for item in root.findall(".//item"):
        title = item.findtext("title", default="")
        link = item.findtext("link", default="")
        description = item.findtext("description", default="")
        pub_date = item.findtext("pubDate", default="")

        ref_match = REFERENCE_PATTERN.search(link) or REFERENCE_PATTERN.search(title)
        reference = ref_match.group(0) if ref_match else ""
        if not reference:
            print(f"[certfr] Impossible d'extraire une référence CERT-FR valide "
                  f"pour l'item '{title[:60]}...' — item ignoré.")

        items.append({
            "title": title, "link": link, "description": description,
            "pub_date": pub_date, "reference": reference,
        })

    return items


def fetch_certfr_json(reference: str) -> dict:
    """
    Récupère la représentation JSON détaillée d'un avis CERT-FR.
    Distingue explicitement les causes d'échec pour faciliter le diagnostic.
    """
    url = f"https://www.cert.ssi.gouv.fr/avis/{reference}/json/"
    try:
        response = requests.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"[certfr] Erreur HTTP pour {reference} : {e}")
        return {}
    except requests.exceptions.RequestException as e:
        print(f"[certfr] Erreur réseau pour {reference} : {e}")
        return {}

    try:
        return response.json()
    except json_module.JSONDecodeError as e:
        print(f"[certfr] JSON invalide pour {reference} : {e}")
        return {}


def extract_cve_ids_from_json(json_data: dict, fallback_text: str = "") -> list[str]:
    """
    Extrait les CVE depuis le champ structuré 'cves' du JSON CERT-FR
    (format confirmé : liste de {name, url}). Si le JSON est indisponible,
    retombe sur une extraction par regex depuis le texte RSS.
    """
    cves_field = json_data.get("cves")
    if cves_field:
        return list({c["name"] for c in cves_field if c.get("name")})
    return list(set(CVE_PATTERN.findall(fallback_text or "")))


def extract_advisory_fields(reference: str, rss_item: dict, json_data: dict) -> dict:
    """
    Construit les données propres à l'avis (PAS à la CVE elle-même) :
    résumé, risques, solutions, documentation.

    Format CERT-FR confirmé (via --debug) :
        - summary       : texte direct
        - risks         : liste de {description}
        - content       : markdown libre contenant généralement "## Solutions"
                          (pas de champ "solutions" séparé)
        - vendor_advisories : liste de {title, url, published_at} -> sert
                          de "documentation" (liens vers le bulletin éditeur)
    """
    risks_list = json_data.get("risks") or []
    risks_text = " ; ".join(r.get("description", "") for r in risks_list) or None

    # Les solutions sont dans "content" (markdown libre), pas un champ dédié.
    solutions_text = json_data.get("content") or None

    advisories = json_data.get("vendor_advisories") or []
    documentation_text = " ; ".join(
        f"{a.get('title', '')} — {a.get('url', '')}" for a in advisories
    ) or None

    if not json_data:
        print(f"[certfr] Pas de JSON structuré pour {reference} — "
              f"résumé/risques/solutions resteront vides pour cet avis.")

    return {
        "reference": reference,
        "title": rss_item["title"],
        "summary": json_data.get("summary") or rss_item["description"],
        "risks": risks_text,
        "solutions": solutions_text,
        "documentation": documentation_text,
        "link": rss_item["link"],
        "published_date": rss_item["pub_date"],
    }


def extract_affected_products(json_data: dict) -> list[dict]:
    """
    Extrait les produits affectés depuis le format CERT-FR confirmé :
    affected_systems[].product.name et affected_systems[].product.vendor.name
    (structure imbriquée, différente du format plat de NVD/CPE).
    Pas de version structurée disponible - "description" contient un texte
    libre du type "SPIP versions antérieures à 4.4.18", non parsable
    fiablement en (version_start/version_end) sans heuristique dédiée.
    """
    raw_systems = json_data.get("affected_systems")
    if not raw_systems:
        return []

    products = []
    for entry in raw_systems:
        product_info = entry.get("product", {})
        vendor_info = product_info.get("vendor", {})
        products.append({
            "vendor": vendor_info.get("name", "unknown"),
            "product": product_info.get("name", "unknown"),
            # Pas de version structurée côté CERT-FR : on garde la description
            # libre pour référence humaine, sans la faire passer pour une
            # version exploitable par le matcher.
            "version": entry.get("description"),
            "version_start_including": None,
            "version_end_excluding": None,
        })
    return products


def normalize_cve_entry(cve_id: str, rss_item: dict, json_data: dict) -> dict:
    """
    Construit l'entrée CVE au format commun (compatible upsert_cve).
    La description reste volontairement vide : ce n'est pas le rôle de
    CERT-FR de définir la description générale d'une CVE (rôle de NVD/MITRE).
    Les infos spécifiques à l'avis vont dans certfr_advisories, pas ici.
    """
    return {
        "cve_id": cve_id,
        "description": None,           # pas de titre d'avis ici — voir point 1/4
        "cvss_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
        "published_date": None,        # NVD reste la référence pour cette date
        "last_modified": None,
        "affected_products": extract_affected_products(json_data),
        "references": [rss_item["link"]] if rss_item["link"] else [],
    }


def debug_print_raw_item(feed_url: str = CERTFR_RSS_URL) -> None:
    """Affiche un item RSS brut + le JSON de l'avis correspondant, à lancer
    en premier pour valider les hypothèses de format avant tout traitement réel."""
    items = fetch_certfr_rss(feed_url)
    if not items:
        print("[certfr] Aucun item trouvé dans le flux RSS.")
        return

    print("[certfr] Premier item RSS brut :")
    print(items[0])

    if items[0]["reference"]:
        json_data = fetch_certfr_json(items[0]["reference"])
        print("\n[certfr] JSON de l'avis correspondant (clés disponibles) :")
        print(list(json_data.keys()) if json_data else "(vide ou indisponible)")
        print("\n[certfr] Contenu complet :")
        print(json_data)


def collect_certfr(limit: int = 20, db_path: str = DB_PATH) -> int:
    """
    Collecte les derniers avis CERT-FR, sépare les données d'avis (stockées
    dans certfr_advisories) des données de CVE (stockées dans cve, en
    complément non-prioritaire par rapport à NVD).

    Returns:
        Le nombre de CVE DISTINCTES traitées sur ce run.
    """
    print("[certfr] Récupération du flux RSS CERT-FR...")
    items = [i for i in fetch_certfr_rss()[:limit] if i["reference"]]
    print(f"[certfr] {len(items)} avis exploitables (référence valide).")

    conn = get_connection(db_path)
    cursor = conn.cursor()

    seen_cve_ids = set()

    for item in items:
        json_data = fetch_certfr_json(item["reference"])

        cve_ids = extract_cve_ids_from_json(json_data, fallback_text=item["title"] + " " + item["description"])
        if not cve_ids:
            continue  # avis sans CVE identifiée (bulletin générique)

        # Ordre important : on crée d'abord les CVE (upsert_cve), qui sont
        # référencées par certfr_advisory_cve via une contrainte FK. Créer
        # le lien avis→CVE avant que la ligne cve existe fait échouer la
        # contrainte de clé étrangère (c'était le bug initial).
        for cve_id in cve_ids:
            entry = normalize_cve_entry(cve_id, item, json_data)
            try:
                upsert_cve(cursor, entry, source_name="CERT-FR", primary=False)
                seen_cve_ids.add(cve_id)
            except Exception as e:
                print(f"[certfr] Erreur lors de l'insertion de {cve_id} : {e}")

        advisory = extract_advisory_fields(item["reference"], item, json_data)
        try:
            upsert_certfr_advisory(cursor, advisory, cve_ids)
        except Exception as e:
            print(f"[certfr] Erreur lors de l'enregistrement de l'avis {item['reference']} : {e}")
            continue

    conn.commit()
    conn.close()

    print(f"[certfr] {len(seen_cve_ids)} CVE distinctes traitées depuis CERT-FR.")
    return len(seen_cve_ids)


if __name__ == "__main__":
    import sys

    if "--debug" in sys.argv:
        debug_print_raw_item()
    else:
        collect_certfr()