import io
import json
import requests
from bs4 import BeautifulSoup

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

MAX_CHARS = 3000
USER_AGENT = "cert-ai-agent/1.0"
JS_RENDER_THRESHOLD = 200


def _extract_html(content: bytes) -> str:
    soup = BeautifulSoup(content, "html.parser")
    for tag in soup(["script", "style", "nav", "footer"]):
        tag.decompose()
    return soup.get_text(separator=" ", strip=True)


def _extract_with_playwright(url: str, timeout_ms: int = 15000) -> str:
    if sync_playwright is None:
        print(
            "[reference_processor] playwright non installé — "
            "'pip install playwright' puis "
            "'python -m playwright install chromium' pour l'activer."
        )
        return ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)
            page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            text = page.inner_text("body")
            browser.close()
            return text
    except Exception as e:
        print(f"[reference_processor] Échec du rendu Playwright pour {url} : {e}")
        return ""


def _extract_pdf(content: bytes) -> str:
    if PdfReader is None:
        print(
            "[reference_processor] pypdf non installé — "
            "'pip install pypdf' pour activer le support PDF."
        )
        return ""

    try:
        reader = PdfReader(io.BytesIO(content))
        return " ".join(page.extract_text() or "" for page in reader.pages)
    except Exception as e:
        print(f"[reference_processor] Erreur d'extraction PDF : {e}")
        return ""


def _extract_csaf_vex(content: bytes) -> str:
    try:
        data = json.loads(content)
        parts = []

        for note in data.get("document", {}).get("notes", []):
            parts.append(note.get("text", ""))

        for vuln in data.get("vulnerabilities", []):
            for note in vuln.get("notes", []):
                parts.append(note.get("text", ""))

            for remediation in vuln.get("remediations", []):
                parts.append(remediation.get("details", ""))

        return " ".join(p for p in parts if p)

    except Exception as e:
        print(f"[reference_processor] Erreur d'extraction CSAF/VEX : {e}")
        return ""


def process_reference(url: str, max_chars: int = MAX_CHARS) -> str:
    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()

    except Exception as e:
        print(f"[reference_processor] Impossible de récupérer {url} : {e}")
        return ""

    content_type = response.headers.get("Content-Type", "").lower()

    if "application/pdf" in content_type or url.lower().endswith(".pdf"):
        text = _extract_pdf(response.content)

    elif "json" in content_type:
        text = _extract_csaf_vex(response.content)
        if not text:
            text = response.text

    elif "xml" in content_type:
        soup = BeautifulSoup(response.content, "xml")
        text = soup.get_text(separator=" ", strip=True)

    elif "html" in content_type or not content_type:
        text = _extract_html(response.content)

        if len(text) < JS_RENDER_THRESHOLD:
            print(
                f"[reference_processor] Contenu trop court ({len(text)} caractères) - "
                f"tentative Playwright pour {url}"
            )

            js_text = _extract_with_playwright(url)

            if len(js_text) > len(text):
                text = js_text

    else:
        print(f"[reference_processor] Format non géré ({content_type}) pour {url}")
        text = ""

    final_text = text[:max_chars]

    print(
        f"[reference_processor] {url} → {len(text)} caractères extraits "
        f"({'tronqué à ' + str(max_chars) if len(text) > max_chars else 'non tronqué'})"
    )

    return final_text


if __name__ == "__main__":
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else None

    if not test_url:
        print("Usage : python reference_processor.py https://exemple.com/advisory")
        sys.exit(1)

    result = process_reference(test_url)

    print(f"--- {len(result)} caractères extraits ---")
    print(result[:500])