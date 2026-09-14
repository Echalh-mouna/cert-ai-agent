````markdown
# CERT AI Agent

## Automatisation de la gestion des vulnérabilités par la Cyber Threat Intelligence et l'intelligence artificielle

CERT AI Agent est un prototype d'agent intelligent conçu pour automatiser le cycle de gestion des vulnérabilités au sein d'une équipe CERT.

Le projet couvre l'ensemble du processus, depuis la collecte des vulnérabilités provenant de plusieurs sources de Cyber Threat Intelligence (CTI), jusqu'à l'identification des équipements concernés, la génération des alertes, la notification des responsables et le suivi de la remédiation.

---

## 🎯 Objectifs du projet

Le projet a pour objectifs de :

- Automatiser la collecte des vulnérabilités depuis plusieurs sources CTI.
- Centraliser et normaliser les informations collectées.
- Assurer la traçabilité des sources associées aux vulnérabilités.
- Dédupliquer et fusionner les informations provenant de différentes sources.
- Identifier les équipements potentiellement concernés par une vulnérabilité.
- Automatiser le matching entre les CVE et l'inventaire des équipements.
- Évaluer et prioriser les vulnérabilités détectées.
- Exploiter un LLM local pour générer et structurer les informations d'alerte.
- Générer automatiquement des fiches de vulnérabilité au format PDF.
- Notifier les responsables concernés par e-mail.
- Suivre l'état de la remédiation.
- Effectuer des relances en cas de vulnérabilité toujours en attente.
- Fournir un tableau de bord pour superviser l'activité du système.

---

## 🏗️ Architecture du projet

```text
                         SOURCES CTI
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
         NVD               CERT-FR              CISA
          │                   │                   │
          │                MA-CERT                │
          │                   │                   │
          └─────────────── CISA KEV ──────────────┘
                              │
                              ▼
                    COLLECTE MULTI-SOURCE
                              │
                              ▼
                     NORMALISATION
                              │
                              ▼
                  DÉDUPLICATION / FUSION
                              │
                              ▼
                       BASE DE DONNÉES
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
         INVENTAIRE DES                ANALYSE / LLM
          ÉQUIPEMENTS                       │
                │                           │
                └─────────────┬─────────────┘
                              ▼
                           MATCHING
                              │
                              ▼
                     AGENT DÉCISIONNEL
                              │
                              ▼
                    GÉNÉRATION DE FICHE
                              │
                              ▼
                        NOTIFICATION
                              │
                              ▼
                        REMÉDIATION
                              │
                              ▼
                       SUIVI / RELANCE
                              │
                              ▼
                         SUPERVISION
````

---

## 🔄 Cycle de traitement

```text
Collecte
   ↓
Normalisation
   ↓
Fusion / Déduplication
   ↓
Analyse
   ↓
Matching avec l'inventaire
   ↓
Décision de l'agent
   ↓
Génération de la fiche
   ↓
Notification
   ↓
Remédiation
   ↓
Suivi
   ↓
Relance
   ↓
Clôture
```

---

# 🌐 Sources CTI

Le système exploite plusieurs sources de Cyber Threat Intelligence :

* **NIST National Vulnerability Database (NVD)**
* **CERT-FR**
* **CISA**
* **MA-CERT**
* **CISA Known Exploited Vulnerabilities (KEV)**

L'utilisation de plusieurs sources permet d'améliorer la couverture des vulnérabilités et de croiser les informations disponibles.

Pour chaque vulnérabilité, les sources associées sont conservées afin d'assurer la traçabilité de l'information.

---

# 🗄️ Base de données

Les données du système sont centralisées dans une base de données relationnelle **SQLite**.

La base permet notamment de gérer :

* les vulnérabilités CVE ;
* les produits affectés ;
* les sources CTI ;
* les associations entre CVE et sources ;
* les équipements ;
* les responsables des équipements ;
* les références utilisées ;
* les décisions prises par l'agent ;
* les informations de remédiation ;
* l'historique des traitements.

Les principales tables comprennent notamment :

```text
cve
cve_sources
sources
products
equipment
references
remediation_status
agent_log
```

---

# 🖥️ Inventaire et matching

Le projet utilise un inventaire d'équipements permettant de représenter les systèmes présents dans l'environnement.

Chaque équipement peut être associé à :

* une entreprise ;
* un fournisseur ;
* un produit ;
* une version ;
* un responsable.

Le module de matching compare les informations des vulnérabilités avec celles de l'inventaire afin d'identifier les équipements potentiellement concernés.

```text
CVE
 │
 ├── Vendor
 ├── Product
 └── Version
        │
        ▼
Inventaire
        │
        ▼
Matching
        │
        ▼
Équipement concerné
        │
        ▼
Responsable identifié
```

Le matching prend notamment en compte les produits et les versions afin d'améliorer l'identification des équipements concernés.

---

# 🤖 Intelligence artificielle

Le projet intègre un **Large Language Model (LLM)** afin d'automatiser la génération et la structuration des informations relatives aux vulnérabilités.

Le modèle utilisé est :

* **Qwen**
* exécuté localement avec **Ollama**

L'utilisation d'un modèle local permet de traiter les informations dans l'environnement d'exécution sans dépendre d'une API LLM externe pour cette étape.

Le LLM est utilisé notamment pour contribuer à la génération des informations nécessaires aux fiches d'alerte.

---

# 🧠 Agent décisionnel

Le composant `agent.py` orchestre le traitement d'une vulnérabilité.

Il s'appuie sur les informations collectées, les résultats du matching et les critères de traitement afin de prendre une décision.

Les décisions peuvent notamment correspondre à :

```text
CVE
 │
 ▼
Analyse
 │
 ▼
Matching
 │
 ▼
Évaluation
 │
 ▼
Décision
 ├── Envoi
 ├── Sans impact
 └── Traitement selon le contexte
```

Les traitements effectués par l'agent sont enregistrés dans la base de données afin de conserver une trace des décisions.

---

# 📄 Génération des fiches d'alerte

Lorsqu'une vulnérabilité est retenue pour traitement, le système génère automatiquement une fiche d'alerte au format PDF.

La fiche peut contenir notamment :

* Identifiant CVE
* Description
* Score CVSS
* Niveau de sévérité
* Informations d'exploitabilité
* Produits affectés
* Équipements concernés
* Responsable
* Informations de remédiation
* Références

Les fiches générées sont enregistrées dans le répertoire :

```text
alerts/
```

---

# 📧 Notification par e-mail

Le système intègre un mécanisme de notification utilisant **SMTP**.

Lorsqu'une vulnérabilité doit être transmise au responsable concerné, le système :

```text
Analyse
   ↓
Génération de la fiche PDF
   ↓
Préparation de l'e-mail
   ↓
Ajout de la fiche en pièce jointe
   ↓
Envoi au responsable
   ↓
Enregistrement du traitement
```

Les messages générés pour les tests peuvent être conservés dans le répertoire :

```text
emails/
```

---

# 🔁 Suivi de la remédiation

Après l'envoi d'une alerte, le système permet de suivre l'évolution de la remédiation.

Les principaux états sont :

```text
Identifiée
    ↓
Notification envoyée
    ↓
En attente
    ↓
Corrigée
    ↓
Clôturée
```

Lorsqu'une vulnérabilité reste en attente, le système peut identifier les alertes nécessitant une relance.

Après confirmation de la correction, l'état peut être mis à jour et une notification de confirmation peut être envoyée au responsable.

---

# 📊 Tableau de bord

Une interface de supervision développée avec **Streamlit** permet de suivre l'activité du système.

Le tableau de bord présente notamment :

* le nombre de CVE collectées ;
* le nombre de CVE critiques ;
* le nombre de matchs effectués ;
* le taux de correction ;
* la répartition selon la sévérité CVSS ;
* les décisions prises par l'agent ;
* la répartition selon les sources CTI ;
* les remédiations en attente ;
* le détail des suivis de remédiation.

Le dashboard permet ainsi d'obtenir une vision globale de l'activité du CERT AI Agent.

---

# 🛠️ Technologies utilisées

| Domaine                   | Technologies                          |
| ------------------------- | ------------------------------------- |
| Langage                   | Python                                |
| Base de données           | SQLite                                |
| CTI                       | NVD, CERT-FR, CISA, MA-CERT, CISA KEV |
| Communication             | API REST                              |
| Intelligence artificielle | LLM                                   |
| Modèle                    | Qwen                                  |
| Exécution LLM             | Ollama                                |
| Supervision               | Streamlit                             |
| Notification              | SMTP                                  |
| Documents                 | PDF                                   |
| Versionnement             | Git / GitHub                          |

---

# 📁 Structure du projet

```text
cert-ai-agent/
│
├── agent.py
├── database.py
├── inventory.py
├── matcher.py
├── mail_generator.py
├── remediation_tracker.py
│
├── data/
│   └── cert_agent.db
│
├── alerts/
│
├── emails/
│
├── docs/
│
├── requirements.txt
│
└── README.md
```

---

# ⚙️ Installation

## 1. Cloner le dépôt

```bash
git clone https://github.com/Echalh-mouna/cert-ai-agent.git
cd cert-ai-agent
```

## 2. Créer un environnement virtuel

```bash
python -m venv .venv
```

## 3. Activer l'environnement virtuel

### Windows

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

## 4. Installer les dépendances

```bash
pip install -r requirements.txt
```

## 5. Installer Ollama

Installer Ollama sur la machine puis récupérer le modèle Qwen utilisé par le projet.

La configuration du modèle dépend de l'environnement local.

---

# ▶️ Utilisation

## Traitement ciblé d'une CVE

Exemple :

```bash
python agent.py CVE-2025-54518 --send
```

Cette commande permet de lancer le traitement ciblé d'une vulnérabilité et, avec l'option `--send`, d'effectuer l'envoi de la notification selon la configuration du système.

---

## Suivi des remédiations

Le suivi peut être exécuté avec :

```bash
python remediation_tracker.py
```

Le tracker permet notamment d'identifier les vulnérabilités en attente et de gérer les relances ou les confirmations de correction.

---

# 🔐 Confidentialité

Le projet a été conçu avec une attention particulière portée à la confidentialité des informations traitées.

L'utilisation de **Qwen avec Ollama** permet d'exécuter le modèle localement.

L'inventaire et les équipements utilisés dans le cadre du prototype sont des données de test et ne représentent pas une infrastructure de production réelle.

Les adresses e-mail utilisées dans les exemples et tests sont également destinées à l'environnement de démonstration.

---

# ⚠️ Limites

Le projet constitue un prototype réalisé dans le cadre d'un projet de fin d'année.

Les principales limites identifiées sont :

* l'inventaire utilisé est un inventaire de test et non une CMDB réelle ;
* la qualité du matching dépend des informations disponibles sur les produits et les versions ;
* les résultats dépendent de la qualité et de la disponibilité des sources CTI ;
* les capacités de génération dépendent du modèle LLM utilisé ;
* l'environnement SMTP utilisé est principalement destiné aux tests ;
* certaines intégrations nécessiteraient des adaptations pour un environnement de production.

---

# 🚀 Perspectives

Les principales évolutions envisagées sont :

* intégration avec une CMDB réelle ;
* ajout de nouvelles sources CTI ;
* amélioration du matching et de la gestion des versions ;
* amélioration de la priorisation des vulnérabilités ;
* enrichissement des capacités de l'agent IA ;
* intégration avec des outils de ticketing ;
* intégration avec les outils d'un SOC/CERT ;
* amélioration du suivi de remédiation ;
* déploiement dans un environnement de production ;
* amélioration du tableau de bord et des capacités de supervision.

---

# 📚 Références

* NIST National Vulnerability Database
  [https://nvd.nist.gov/](https://nvd.nist.gov/)

* NVD Vulnerability APIs
  [https://nvd.nist.gov/developers/vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities)

* CERT-FR
  [https://www.cert.ssi.gouv.fr/](https://www.cert.ssi.gouv.fr/)

* CISA
  [https://www.cisa.gov/](https://www.cisa.gov/)

* CISA Known Exploited Vulnerabilities Catalog
  [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

* Ollama
  [https://ollama.com/](https://ollama.com/)

* Streamlit
  [https://streamlit.io/](https://streamlit.io/)

---

# 📌 Projet

**CERT AI Agent**

Automatisation de la gestion des vulnérabilités par la Cyber Threat Intelligence et l'intelligence artificielle.

**Projet de fin d'année — Cybersécurité & Cloud Computing**

**Développé par : Mouna Echalh**

**Entreprise : SEKERA**

**Encadré par : M. Tarek RADAH — Senior Security Consultant & SOC Manager, SEKERA**

**Période : 13 juillet 2026 — 13 septembre 2026**

---

# 🔗 Repository

[https://github.com/Echalh-mouna/cert-ai-agent](https://github.com/Echalh-mouna/cert-ai-agent)

```
```
