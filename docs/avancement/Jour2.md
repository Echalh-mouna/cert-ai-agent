# Avancement – Jour 2

## Objectif

Identifier les principales sources officielles de Cyber Threat Intelligence (CTI) qui alimenteront le futur système CERT, puis analyser leur mode d'accès afin de préparer l'automatisation de la collecte.

---

## Travail réalisé

J'ai étudié les principales sources de Cyber Threat Intelligence utilisées par les CERT et les équipes de veille en cybersécurité. L'objectif était d'identifier les sources les plus pertinentes, d'évaluer leur fiabilité et de comprendre les mécanismes permettant de récupérer automatiquement les informations qu'elles publient (API, RSS, JSON, XML, etc.).

Le tableau suivant résume les principales caractéristiques de chaque source.

| Source | Type d'accès | Format | Fiabilité | Limites |
|--------|--------------|--------|-----------|----------|
| CERT-FR | Flux RSS | RSS / XML | Élevée (source officielle française) | Pas d'API REST structurée ; contenu textuel nécessitant une phase d'extraction et de structuration. |
| NIST NVD | API REST publique | JSON | Très élevée (base mondiale de référence des vulnérabilités CVE) | Limitation du nombre de requêtes sans clé API ; une clé API est recommandée pour les collectes intensives. |
| MITRE CVE | Base CVE / API | JSON | Très élevée (autorité officielle d'attribution des identifiants CVE) | Fournit principalement les informations d'identification des CVE ; les métriques d'évaluation (CVSS, CPE, CWE) sont davantage détaillées dans NVD. |
| CISA Advisories | API REST publique | JSON | Élevée (agence gouvernementale américaine) | Les publications sont principalement orientées vers les infrastructures et organisations américaines. |
| CISA KEV | API REST publique | JSON | Très élevée (liste des vulnérabilités activement exploitées) | Ne couvre que les vulnérabilités dont l'exploitation active est confirmée ; ne constitue pas une liste exhaustive des CVE. |
| MA-CERT | Site Web (à confirmer) | HTML (à confirmer) | Source officielle nationale | Absence d'API publique ou de flux structuré confirmés ; l'automatisation pourrait nécessiter du web scraping. |

---

## Workflow cible

```
Sources CTI officielles
(CERT-FR, NIST, CISA, MA-CERT, MITRE)
        ↓
Collecte automatique
        ↓
Analyse des vulnérabilités
(criticité, produits, versions concernées)
        ↓
Identification des équipements impactés
        ↓
Génération d'une fiche d'alerte
        ↓
Diffusion ciblée
        ↓
Suivi de la remédiation
```

---

## Ce que j'ai retenu

- Toutes les sources ne proposent pas le même mode d'accès.
- NIST NVD est la source la plus adaptée pour commencer le développement grâce à son API REST publique et à son format JSON.
- CERT-FR fournit principalement un flux RSS qui nécessitera une étape de parsing.
- MA-CERT ne propose pas, à ce stade, de mécanisme d'accès structuré identifié ; un scraping pourrait être nécessaire.
- Les autres sources (CISA et MITRE) permettront ensuite d'enrichir les informations collectées.

---

## Prochaine étape

Commencer le développement du premier collecteur CTI en utilisant **NIST NVD** comme source unique.

Objectifs :

- développer `collector.py` ;
- se connecter à l'API REST de NIST NVD ;
- récupérer automatiquement les dernières CVE ;
- parser la réponse JSON ;
- préparer les données qui serviront à la génération des futures fiches d'alerte.

Le choix de commencer par NIST NVD permet de valider le pipeline de collecte sur une source officielle, stable et bien documentée avant d'intégrer progressivement CERT-FR, CISA, MITRE et MA-CERT.