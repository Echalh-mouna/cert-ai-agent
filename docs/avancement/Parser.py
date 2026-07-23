import json 

def extract_description(cve_data: dict)->str:
    descriptions = cve_data.get("descriptions",[])
    for desc in descriptions: 
        if desc.get("lang") == "en": 
            return desc.get("value","")
    return ""     

def extract_cvss(cve_data: dict) -> dict:
    metrics = cve_data.get("metrics",{})

    for version_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics and metrics[version_key]:
            metric = metrics[version_key][0]
            cvss_data = metric.get("cvssData",{})
            return{
                "score":cvss_data.get("baseScore"),
                "severity":metric.get("baseSeverity",cvss_data.get("baseSeverity")),
                "vector":cvss_data.get("vectorString"),
            }
    return{"score" : None,"severity":None,"vector": None}


def extract_affected_products(cve_data: dict) -> list[dict]:

    products = []
    configurations = cve_data.get("configurations",[])

    for config in configurations:
        for node in config.get("nodes",[]):
            for cpe_match in node.get("cpeMatch",[]):
                if cpe_match.get("vulnerable"):
                    criteria = cpe_match.get("criteria","")
                    parts = criteria.split(":")
                    vendor = parts[3] if len(parts)>3 else "unknown"
                    product = parts[4] if len(parts)>4 else "unknown"
                    version = parts[5] if len(parts)>5 else "unknown"

                    products.append({
                        "vendor":vendor,
                        "product":product,
                        "version":version,
                        "version_start_including": cpe_match.get("versionStartIncluding"),
                        "version_end_excluding": cpe_match.get("versionEndExcluding"),

                    })

    return products

def extract_references(cve_data:dict)->list[str]:
  return[ref.get("url") for ref in cve_data.get("references",[]) if ref.get("url")]


def parse_cve(raw_entry: dict)-> dict:

    cve_data = raw_entry.get("cve",{})
    cvss = extract_cvss(cve_data)

    return{
        "cve_id":cve_data.get("id"),
        "description":extract_description(cve_data),
        "cvss_score" :cvss["score"],
        "cvss_severity":cvss["severity"],
        "cvss_vector": cvss["vector"],
        "published_date": cve_data.get("published"),
        "last_modified": cve_data.get("lastModified"),
        "affected_products": extract_affected_products(cve_data),
        "references": extract_references(cve_data),
        
    }


def parse_all(input_path: str = "data/raw_cves.json", output_path: str = "data/parsed_cves.json") -> int:
    with open(input_path, "r", encoding="utf-8") as f:
        raw_cves = json.load(f)
 
    parsed = []
    errors = 0
 
    for entry in raw_cves:
        try:
            parsed.append(parse_cve(entry))
        except Exception as e:
            errors += 1
            print(f"[parser] Erreur lors du parsing d'une entrée : {e}")
 
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2, ensure_ascii=False)
 
    print(f"[parser] {len(parsed)} CVE parsées avec succès, {errors} erreurs.")
    print(f"[parser] Résultat sauvegardé dans {output_path}")
 
    return len(parsed)

if __name__ == "__main__":
    parse_all()