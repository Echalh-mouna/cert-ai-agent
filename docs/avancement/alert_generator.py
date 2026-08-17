import os
import sqlite3
from datetime import datetime

from xhtml2pdf import pisa

from database import get_connection, DB_PATH
from reference_processor import process_reference

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:7b"

ALERTS_DIR = "alerts"

PDF_CSS = """
<style>
    body { font-family: Helvetica, sans-serif; font-size: 11px; color: #222; }
    h1 { font-size: 18px; color: #1a1a1a; }
    h2 { font-size: 14px; color: #1a1a1a; margin-top: 16px; border-bottom: 1px solid #ccc;
         padding-bottom: 2px; }
    table { border-collapse: collapse; width: 100%; margin: 8px 0; }
    th, td { border: 1px solid #999; padding: 4px 8px; text-align: left; font-size: 10px; }
    th { background-color: #eee; }
    .synthese th { background-color: #d9534f; color: white; }
    p { line-height: 1.4; }
    .refs { font-size: 9px; color: #444; }
</style>
"""


def call_llm(prompt: str, max_tokens: int = 800) -> str:
    response = requests.post(OLLAMA_URL, json={
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": max_tokens,

            "temperature": 0.1,

            "top_p": 0.8,

            "repeat_penalty": 1.1,},
    }, timeout=600)
    response.raise_for_status()
    return response.json()["response"]


def get_cve_context(cve_id: str, db_path: str = DB_PATH) -> dict:
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,))
    cve_row = cursor.fetchone()
    if not cve_row:
        conn.close()
        raise ValueError(f"CVE {cve_id} introuvable en base")

    cursor.execute("""
        SELECT p.product, p.version, v.name AS vendor
        FROM products p LEFT JOIN vendors v ON p.vendor_id = v.vendor_id
        WHERE p.cve_id = ?
    """, (cve_id,))
    products = [dict(row) for row in cursor.fetchall()]

    cursor.execute('SELECT url FROM "references" WHERE cve_id = ?', (cve_id,))
    references = [row["url"] for row in cursor.fetchall()
                  if "known-exploited-vulnerabilities-catalog" not in row["url"]]

    conn.close()
    return {**dict(cve_row), "products": products, "references": references}


def analyze_references_with_llm(cve_context: dict, reference_texts: list[str]) -> dict:
    references_content = "\n\n---\n\n".join(
        f"[Source : {url}]\n{text}"
        for url, text in zip(cve_context["references"], reference_texts) if text
    )

    if not references_content:
        return {
            "risk_analysis": "Aucun contenu de référence exploitable n'a pu être récupéré. "
                              "Se référer à la description CVE ci-dessus.",
            "remediation": "Aucune mesure de remédiation alternative trouvée dans les références "
                            "disponibles. Vérifier manuellement l'advisory du vendor.",
        }

    prompt = f"""Tu es un analyste CERT. À partir UNIQUEMENT du contenu ci-dessous, réponds
au format suivant. Si une information n'est pas présente, écris exactement
"Non précisé dans les sources." plutôt que de l'inventer.

Règles obligatoires :



- Utilise uniquement les informations présentes dans les références.

- N'utilise jamais tes connaissances personnelles.

- N'invente aucune information.

- Si une information est absente, écris exactement :

  Non précisé dans les sources.

- Ne propose jamais une mesure de sécurité qui n'est pas explicitement mentionnée.

- Réponds uniquement en français.

- Réponds uniquement sous ce format.

Description CVE : {cve_context['description']}

Contenu des références :
{references_content}

RISQUE: <comment la faille peut être exploitée et impact d'une compromission>
REMEDIATION: <mesures mentionnées - patch, durcissement, cloisonnement, contournement>"""

    try:
        text = call_llm(prompt)
    except requests.RequestException as e:
        return {
            "risk_analysis": f"Erreur lors de l'appel du modèle local : {e}",
            "remediation": "Analyse indisponible.",
        }

    risk = text.split("REMEDIATION:")[0].replace("RISQUE:", "").strip()
    remediation = text.split("REMEDIATION:")[1].strip() if "REMEDIATION:" in text else "Non précisé."

    return {"risk_analysis": risk, "remediation": remediation}


def _products_table_html(products: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{p['vendor'] or 'N/A'}</td><td>{p['product'] or 'N/A'}</td>"
        f"<td>{p['version'] or 'N/A'}</td></tr>"
        for p in products
    ) or "<tr><td colspan='3'>Non spécifié dans NVD</td></tr>"

    return f"""<table>
        <tr><th>Vendor</th><th>Produit</th><th>Version</th></tr>
        {rows}
    </table>"""


def build_fiche_html(cve_context: dict, llm_analysis: dict) -> str:
    exploit_status = ("Oui (confirmé par CISA KEV)" if cve_context["exploit_public"]
                       else "Non confirmé à ce jour")
    products_table = _products_table_html(cve_context["products"])
    refs_html = "".join(f"<li>{url}</li>" for url in cve_context["references"]) \
        or "<li>Aucune référence disponible.</li>"

    body = f"""
    <h1>Fiche d'alerte — {cve_context['cve_id']}</h1>

    <h2>Tableau de synthèse</h2>
    <table class="synthese">
        <tr><th>Élément</th><th>Synthèse</th></tr>
        <tr><td>Applicabilité</td><td>Voir tableau des produits/versions concernés ci-dessous</td></tr>
        <tr><td>Risque</td><td>Score CVSS {cve_context['cvss_score']} ({cve_context['cvss_severity']})</td></tr>
        <tr><td>Exploitabilité</td><td>{exploit_status}</td></tr>
        <tr><td>Remédiation</td><td>Voir section détaillée ci-dessous</td></tr>
    </table>

    <h2>1. Applicabilité — versions et composants concernés</h2>
    {products_table}

    <h2>2. Risque</h2>
    <p><b>Description officielle (NVD) :</b><br/>{cve_context['description']}</p>
    <p><b>Analyse détaillée :</b><br/>{llm_analysis['risk_analysis']}</p>

    <h2>3. Exploitabilité</h2>
    <p><b>Exploit public confirmé (CISA KEV) :</b> {exploit_status}<br/>
       <b>Score CVSS :</b> {cve_context['cvss_score']}<br/>
       <b>Vecteur :</b> {cve_context['cvss_vector']}</p>

    <h2>4. Remédiation</h2>
    <p>{llm_analysis['remediation']}</p>

    <h2>Références</h2>
    <ul class="refs">{refs_html}</ul>

    <p class="refs"><i>Fiche générée automatiquement le {datetime.now().strftime('%Y-%m-%d %H:%M')}
    — CERT AI Agent</i></p>
    """
    return f"<html><head>{PDF_CSS}</head><body>{body}</body></html>"


def generate_alert(cve_id: str, save: bool = True) -> str:
    print(f"[alert_generator] Génération de la fiche pour {cve_id}...")

    cve_context = get_cve_context(cve_id)
    reference_texts = [process_reference(url) for url in cve_context["references"][:3]]
    llm_analysis = analyze_references_with_llm(cve_context, reference_texts)
    html = build_fiche_html(cve_context, llm_analysis)

    pdf_path = ""
    if save:
        os.makedirs(ALERTS_DIR, exist_ok=True)
        pdf_path = os.path.join(ALERTS_DIR, f"{cve_id}.pdf")
        with open(pdf_path, "wb") as f:
            result = pisa.CreatePDF(html, dest=f)
        if result.err:
            print(f"[alert_generator] Erreur lors de la génération du PDF pour {cve_id}")
            pdf_path = ""
        else:
            print(f"[alert_generator] Fiche PDF sauvegardée dans {pdf_path}")

    return pdf_path


if __name__ == "__main__":
    import sys

    cve_id = sys.argv[1] if len(sys.argv) > 1 else None
    if not cve_id:
        print("Usage : python alert_generator.py CVE-2025-12345")
        sys.exit(1)

    generate_alert(cve_id)