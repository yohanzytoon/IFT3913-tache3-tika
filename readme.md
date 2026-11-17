# Tâche 3 — Semgrep et intégration continue dans Tika

| Nom complet | Identifiant GitHub |
|---|---|
| Yohan Zytoon | yohanzytoon |
| Zouhair El Yani | Zouhair-36 |

**État : partie de Yohan implémentée; travail du binôme encore en cours.**

- [Rapport de Yohan : CI et trois vulnérabilités](docs-tache3/RAPPORT_YOHAN.md)
- [Preuves et validation](docs-tache3/VALIDATION.md)
- [Travail restant pour Zouhair](docs-tache3/HANDOFF.md)
- [Branche contenant les trois vulnérabilités](https://github.com/yohanzytoon/IFT3913-tache3-tika/tree/yohan/vulnerabilities)
- [Workflow modifié](.github/workflows/main-jdk17-build.yml)

La branche `main` conserve le code sécurisé. La branche `yohan/vulnerabilities` contient des vulnérabilités introduites volontairement pour le cours : ne pas utiliser cette branche en production. La CI doit signaler leur introduction par un échec.

La remise complète nécessite encore quatre types distincts, la comparaison finale et l'action réutilisable de rickroll. Le rapport de Yohan contient les limites, les commandes reproductibles et la déclaration d'assistance par IA.
