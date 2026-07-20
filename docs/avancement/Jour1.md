# Rapport Journalier — Compréhension du rôle d'un CERT et cadrage du projet

## Projet

**Conception et Développement d'un Agent IA pour l'Automatisation des Activités d'un CERT**

**Semaine :** 01 — État de l'art et compréhension du métier CERT

**Jour :** 01

**Intitulé :** Compréhension du rôle d'un CERT et cadrage du projet

**Date :** 20/07/2026

---

# 1. Introduction

Cette première journée est consacrée à la compréhension du contexte du projet ainsi qu'au rôle d'un **Computer Emergency Response Team (CERT)** dans la gestion des incidents de cybersécurité. L'objectif est d'identifier les missions réalisées quotidiennement par un consultant CERT, de comprendre le processus de veille en cybersécurité et de définir les bases du futur agent IA qui automatisera ces activités.

---

# 2. Objectifs de la journée

Les objectifs fixés pour cette première journée sont les suivants :

* Comprendre le rôle et les missions d'un CERT.
* Identifier les principales activités réalisées par un consultant CERT.
* Comprendre le processus actuel de veille en cybersécurité.
* Définir le périmètre fonctionnel du futur agent IA.
* Identifier les premières fonctionnalités qui pourront être automatisées.

---

# 3. Présentation du projet

Le projet consiste à concevoir et développer un **Agent IA** capable d'automatiser les principales activités réalisées par un consultant CERT.

L'agent devra assurer une veille continue en cybersécurité en se connectant directement aux sources officielles de Cyber Threat Intelligence (CTI). Il analysera les nouvelles vulnérabilités et menaces, générera automatiquement des fiches d'alerte adaptées aux équipements concernés, notifiera les responsables concernés et assurera le suivi des actions de remédiation jusqu'à la correction des vulnérabilités.

L'objectif est d'automatiser l'ensemble du cycle de traitement des vulnérabilités réalisé aujourd'hui de manière manuelle par les équipes CERT.

---

# 4. Analyse du contexte

Les équipes CERT ont pour mission d'assurer une veille permanente afin d'identifier les nouvelles vulnérabilités, les campagnes de cyberattaques, les malwares émergents ainsi que les nouvelles techniques utilisées par les attaquants.

Lorsqu'une nouvelle vulnérabilité est publiée, le consultant CERT doit généralement :

* consulter plusieurs sources officielles de Cyber Threat Intelligence ;
* analyser la vulnérabilité ainsi que son niveau de criticité ;
* identifier les produits et versions concernés ;
* déterminer quelles organisations ou quels équipements sont impactés ;
* rédiger une fiche d'alerte contenant les informations essentielles ;
* transmettre cette fiche uniquement aux personnes concernées ;
* assurer ensuite le suivi de l'application des correctifs.

Ces différentes tâches sont répétitives et nécessitent de consulter quotidiennement plusieurs sources d'information, ce qui représente un travail important pouvant être automatisé par un agent IA.

---

# 5. Objectifs fonctionnels du projet

Le futur agent IA devra être capable de :

* Collecter automatiquement les informations provenant des sources CTI officielles.
* Détecter les nouvelles vulnérabilités et menaces.
* Analyser les produits et versions impactés.
* Générer automatiquement une fiche d'alerte structurée.
* Identifier les équipements concernés au sein d'une organisation.
* Notifier automatiquement les responsables concernés.
* Assurer le suivi de la remédiation jusqu'à l'application des correctifs.

---

# 6. Périmètre du projet

Le projet couvrira principalement les fonctionnalités suivantes :

* Veille automatisée en cybersécurité.
* Collecte d'informations depuis les sources CTI officielles.
* Analyse des vulnérabilités (CVE).
* Génération automatique de fiches d'alerte.
* Notification ciblée des personnes concernées.
* Suivi des actions de remédiation.
* Relance automatique en cas de non-correction des vulnérabilités.

---

# 7. Travaux réalisés

Au cours de cette première journée, les activités suivantes ont été réalisées :

* Analyse du sujet présenté par l'encadrant.
* Compréhension du fonctionnement général d'un CERT.
* Étude des principales missions d'un consultant CERT.
* Identification des différentes étapes du processus de gestion des vulnérabilités.
* Définition du périmètre général du futur agent IA.
* Préparation de la structure du projet et de la documentation de suivi.

---

# 8. Livrables réalisés

Les livrables produits sont les suivants :

* Synthèse du rôle d'un CERT.
* Description du workflow actuel d'un consultant CERT.
* Définition des objectifs du projet.
* Première note de cadrage fonctionnelle.

---

# 9. Difficultés rencontrées

Aucune difficulté majeure n'a été rencontrée durant cette première journée.

Les travaux ont principalement porté sur l'analyse du sujet, la compréhension du contexte métier et la définition des bases du projet.

---

# 10. Conclusion

Cette première journée a permis de comprendre le fonctionnement d'un CERT ainsi que les différentes étapes du traitement des vulnérabilités. Elle constitue une base essentielle pour la suite du projet, qui portera sur l'étude des sources officielles de Cyber Threat Intelligence et sur la conception de l'architecture de l'agent IA.

---

# 11. Travail prévu pour le Jour 02

Les activités prévues pour la prochaine journée sont les suivantes :

* Étudier les principales sources officielles de Cyber Threat Intelligence (CISA, NIST NVD, CERT-FR, MA-CERT et MITRE).
* Comprendre les différents formats de diffusion des informations (API REST, RSS, XML et JSON).
* Tester manuellement l'accès à ces différentes sources.
* Réaliser un premier schéma du workflow de collecte des informations.
* Préparer le futur module de collecte automatique qui sera intégré à l'agent IA.
