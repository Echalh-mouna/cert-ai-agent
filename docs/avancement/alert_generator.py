import os

import sqlite3

from datetime import datetime



import requests



from database import get_connection, DB_PATH

from reference_processor import process_reference



OLLAMA_URL = "http://localhost:11434/api/generate"

OLLAMA_MODEL = "qwen2.5:7b"



ALERTS_DIR = "alerts"





def call_llm(prompt: str, max_tokens: int = 800) -> str:

    response = requests.post(

        OLLAMA_URL,

        json={

            "model": OLLAMA_MODEL,

            "prompt": prompt,

            "stream": False,

            "options": {

                "num_predict": max_tokens,

                "temperature": 0.1,

                "top_p": 0.8,

                 "repeat_penalty": 1.1,

            },

        },

        timeout=600,

    )



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



    cursor.execute(

        """

        SELECT p.product, p.version, v.name AS vendor

        FROM products p

        LEFT JOIN vendors v ON p.vendor_id = v.vendor_id

        WHERE p.cve_id = ?

        """,

        (cve_id,),

    )



    products = [dict(row) for row in cursor.fetchall()]



    cursor.execute(

        'SELECT url FROM "references" WHERE cve_id = ?',

        (cve_id,),

    )



    references = [row["url"] for row in cursor.fetchall()]



    conn.close()



    return {

        **dict(cve_row),

        "products": products,

        "references": references,

    }





def analyze_references_with_llm(

    cve_context: dict,

    references: list[str],

    reference_texts: list[str],

) -> dict:



    references_content = "\n\n---\n\n".join(

        f"[Source : {url}]\n{text}"

         for url, text in zip(references, reference_texts)

        if text

    )



    if not references_content:

        return {

            "risk_analysis":

                "Aucun contenu de référence exploitable n'a pu être récupéré. "

                "Se référer à la description CVE ci-dessus.",

            "remediation":

                "Aucune mesure de remédiation alternative trouvée dans les références disponibles. "

                "Vérifier manuellement l'advisory du vendor.",

        }



    prompt = f"""

Tu es un analyste CERT expérimenté.



Tu dois rédiger une synthèse STRICTEMENT basée sur les références officielles fournies.



Règles obligatoires :



- Utilise uniquement les informations présentes dans les références.

- N'utilise jamais tes connaissances personnelles.

- N'invente aucune information.

- Si une information est absente, écris exactement :

  Non précisé dans les sources.

- Ne propose jamais une mesure de sécurité qui n'est pas explicitement mentionnée.

- Réponds uniquement en français.

- Réponds uniquement sous ce format.



Description officielle NVD :



{cve_context['description']}



Références :



{references_content}



Réponse :



RISQUE:

...



REMEDIATION:

...

"""
   

    try:

       text = call_llm(prompt)

    except requests.RequestException as e:

      return {

        "risk_analysis": f"Erreur lors de l'appel du modèle local : {e}",

        "remediation": "Analyse indisponible."

    }



    risk = text.split("REMEDIATION:")[0].replace("RISQUE:", "").strip()



    remediation = (

        text.split("REMEDIATION:")[1].strip()

        if "REMEDIATION:" in text

        else "Non précisé."

    )



    return {

        "risk_analysis": risk,

        "remediation": remediation,

    }





def build_fiche(cve_context: dict, llm_analysis: dict) -> str:

    products_str = "\n".join(
        f"| {p['vendor'] or 'N/A'} | {p['product'] or 'N/A'} | {p['version'] or 'N/A'} |"
        for p in cve_context["products"]
    ) or "| Non spécifié dans NVD | - | - |"

    exploit_status = (
        "Oui (confirmé par CISA KEV)"
        if cve_context["exploit_public"]
        else "Non confirmé à ce jour"
    )

    return f"""# Fiche d'alerte — {cve_context['cve_id']}

## Tableau de synthèse

| Élément | Synthèse |
|---|---|
| **Applicabilité** | Voir tableau des produits/versions concernés ci-dessous |
| **Risque** | Score CVSS {cve_context['cvss_score']} ({cve_context['cvss_severity']}) |
| **Exploitabilité** | {exploit_status} |
| **Remédiation** | Voir section détaillée ci-dessous |

## 1. Applicabilité

| Vendor | Produit | Version |
|---|---|---|
{products_str}

## 2. Risque

**Description officielle (NVD) :**

{cve_context['description']}

**Analyse détaillée :**

{llm_analysis['risk_analysis']}

## 3. Exploitabilité

**Exploit public confirmé (CISA KEV) :**

{exploit_status}

**Score CVSS :**

{cve_context['cvss_score']}

**Vecteur :**

{cve_context['cvss_vector']}

## 4. Remédiation

{llm_analysis['remediation']}

## Références

{chr(10).join(f"- {url}" for url in cve_context["references"]) or "Aucune référence disponible."}

---

*Fiche générée automatiquement le {datetime.now().strftime('%Y-%m-%d %H:%M')}*
"""





def generate_alert(cve_id: str, save: bool = True) -> str:



    print(f"[alert_generator] Génération de la fiche pour {cve_id}...")



    cve_context = get_cve_context(cve_id)



  



    references = [

    url 

    for url in cve_context["references"]

    if "known-exploited-vulnerabilities-catalog" not in url

][:3]





    reference_texts = [

    process_reference(url)

    for url in references

]



    llm_analysis = analyze_references_with_llm(

        cve_context,

        references,

        reference_texts,

    )



    fiche = build_fiche(

        cve_context,

        llm_analysis,

    )



    if save:

        os.makedirs(ALERTS_DIR, exist_ok=True)



        output_path = os.path.join(

            ALERTS_DIR,

            f"{cve_id}.md",

        )



        with open(output_path, "w", encoding="utf-8") as f:

            f.write(fiche)



        print(f"[alert_generator] Fiche sauvegardée dans {output_path}")



    return fiche





if __name__ == "__main__":



    import sys



    cve_id = sys.argv[1] if len(sys.argv) > 1 else None



    if not cve_id:

        print("Usage : python alert_generator.py CVE-2025-12345")

        sys.exit(1)



    fiche = generate_alert(cve_id)



    print("\n" + "=" * 60)

    print(fiche)