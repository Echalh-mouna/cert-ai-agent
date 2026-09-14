# CERT AI Agent

### Automatisation de la gestion des vulnérabilités par la Cyber Threat Intelligence et l’intelligence artificielle

CERT AI Agent est un prototype d’agent intelligent conçu pour automatiser le cycle de gestion des vulnérabilités au sein d’une équipe CERT.

Le système collecte des informations de vulnérabilités provenant de plusieurs sources de Cyber Threat Intelligence (CTI), les normalise et les centralise, identifie les équipements potentiellement concernés, génère des fiches d’alerte à l’aide d’un LLM local, puis automatise la notification et le suivi de la remédiation.

---

## 🎯 Objectifs

Le projet vise à réduire les tâches manuelles liées au traitement des vulnérabilités et à améliorer la rapidité et la traçabilité du processus.

Les principaux objectifs sont :

- Automatiser la collecte de vulnérabilités depuis plusieurs sources CTI ;
- Centraliser et normaliser les informations collectées ;
- Éviter les doublons et conserver la provenance des informations ;
- Corréler les vulnérabilités avec l’inventaire des équipements ;
- Identifier les équipements potentiellement affectés ;
- Analyser et prioriser les vulnérabilités ;
- Générer automatiquement des fiches d’alerte ;
- Utiliser un LLM local pour l’enrichissement et la structuration des informations ;
- Notifier les responsables concernés ;
- Suivre l’état de la remédiation ;
- Automatiser les relances ;
- Fournir une vue de supervision du traitement.

---

## 🏗️ Architecture

Le système repose sur une architecture modulaire permettant de séparer les différentes responsabilités du processus.

```text
                    SOURCES CTI
                        │
        ┌───────────────┼────────────────┐
        │               │                │
       NVD           CERT-FR           CISA
        │                                │
        └───────────────┬────────────────┘
                        │
                  COLLECTE MULTI-SOURCE
                        │
                        ▼
                 NORMALISATION
                        │
                        ▼
              FUSION / DÉDUPLICATION
                        │
                        ▼
                  BASE DE DONNÉES
                        │
             ┌──────────┴──────────┐
             │                     │
             ▼                     ▼
       INVENTAIRE             ANALYSE / IA
       ÉQUIPEMENTS                 │
             │                     │
             └──────────┬──────────┘
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
