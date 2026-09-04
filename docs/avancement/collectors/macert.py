"""
collectors/macert.py

⚠️ SOURCE NON IMPLÉMENTÉE — par respect des règles du site, pas par
limitation technique.

Contrairement à CISA (flux RSS supprimé, voir collectors/cisa.py), MA-CERT
n'a pas été écarté pour une raison technique : le site dgssi.gov.ma ne
propose ni flux RSS ni API JSON pour ses bulletins de sécurité
(https://www.dgssi.gov.ma/fr/bulletins-securite), mais surtout, son fichier
robots.txt interdit EXPLICITEMENT l'accès automatisé.

Vérification (à relancer pour confirmer, la règle peut évoluer) :
    python -c "import requests; print(requests.get('https://www.dgssi.gov.ma/robots.txt').text)"

Aucun code de requête vers les pages de contenu n'a été écrit dans ce
fichier : construire un scraper qui contourne un robots.txt va à l'encontre
des règles posées par le site lui-même, et n'a pas sa place dans ce projet,
quelle que soit la faisabilité technique.

Si un accès officiel devient disponible (API partenaire, accès institutionnel
réservé aux administrations, flux RSS futur), ce fichier sera le point
d'implémentation naturel, sur le même modèle que collectors/certfr.py
(upsert_cve avec primary=False, table d'avis dédiée si le contenu s'y prête).

Voir README_semaine4.md, section 5, pour le détail de cette décision.
"""

# Intentionnellement vide de toute logique de collecte.