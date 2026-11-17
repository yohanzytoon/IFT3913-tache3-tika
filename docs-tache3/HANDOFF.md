# Pour Zouhair — état de la partie de Yohan

La partie de Yohan comprend le dépôt et sa référence, le contrôle Semgrep du workflow, trois types avec leurs preuves, et leur documentation. Les types déjà utilisés sont **XXE (CWE-611)**, **certificats TLS non validés (CWE-295)** et **permissions excessives des fichiers (CWE-276)**.

## Ton périmètre

1. Quatre autres types distincts, dans les modules autorisés, avec pour chacun code compilable, règle Semgrep vérifiée, explication et preuve. Pistes à vérifier : injection de commande dans OCR, traversée de chemin, désérialisation dangereuse dans serialization, et un quatrième type réellement pertinent pour Tika. Évite de compter une autre forme de permissions/TLS/XXE comme un nouveau type.
2. L'action réutilisable de rickroll et une vraie exécution où un test échoue. Le job `core-tests` du workflow possède déjà une étape `id: tests`; ajoute ton invocation après cette étape et conserve le statut d'échec. Préfère un déclenchement confirmé par les rapports Surefire à un déclenchement sur n'importe quelle erreur Maven.
3. La comparaison finale des rapports avant/après pour les sept types. Les résultats de Yohan sont sous `docs-tache3/evidence/`.

## Reprendre

```sh
git clone https://github.com/yohanzytoon/IFT3913-tache3-tika.git
cd IFT3913-tache3-tika
git switch -c zouhair/vulnerabilities origin/yohan
```

Ajoute les règles existantes nécessaires dans `.semgrep/rules/` avec leur source exacte et licence, puis vérifie leur comportement. Le workflow inclut automatiquement les YAML supplémentaires et analyse les cinq modules permis. Une alerte héritée ne compte pas comme une nouvelle vulnérabilité.

Le tag `tache3-clean` doit rester immuable. Pour la comparaison finale, utilise le même moteur et le même jeu complet de règles sur la référence et sur les sept changements; ne compare pas un rapport à trois règles avec un rapport à sept règles.

La CI rouge de la branche vulnérable est attendue. Pour prouver ton rickroll indépendamment, pars de `main`, introduis un échec JUnit contrôlé, conserve le lien d'exécution puis rétablis le test. Aucun message ne t'a été envoyé automatiquement et aucune invitation GitHub n'a été envoyée.

Ensemble : relire le rapport, vérifier les sept types et les liens, puis soumettre le seul README du dépôt de cours avant le 17 novembre 2026 à 17 h EST. La soumission finale n'a pas encore été ouverte.
