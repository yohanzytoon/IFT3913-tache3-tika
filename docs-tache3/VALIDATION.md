# Validation de la partie de Yohan

## Périmètre et résultat attendu

Yohan : contrôle Semgrep, XXE (CWE-611), validation TLS désactivée (CWE-295) et permissions excessives (CWE-276). Les quatre autres types, le rickroll et la comparaison finale des sept types sont attribués à Zouhair dans [HANDOFF.md](HANDOFF.md).

**La branche volontairement vulnérable doit échouer au contrôle de sécurité.** Quatre alertes correspondent à trois types : une XXE, deux méthodes du même gestionnaire TLS et une modification des permissions. Le code de sortie `1` est donc la preuve attendue. Il ne faut ni supprimer les règles, ni ignorer ce code pour rendre cette démonstration verte.

## Exécution GitHub Actions vérifiée

[Exécution PR 43999578020](https://github.com/yohanzytoon/IFT3913-tache3-tika/actions/runs/43999578020), tête `f53c27dcb1c3b0c5a101bb115dea50bb45ed2849` :

| Vérification | Résultat observé |
|---|---|
| Installation du scanner épinglé | Réussie |
| Tests unitaires du contrôle, version de ce commit | 12 réussis |
| [Contrôle Semgrep](https://github.com/yohanzytoon/IFT3913-tache3-tika/actions/runs/43999578020/job/133759998258) | `new_findings; 4 finding(s); exit 1` : échec attendu |
| [Tests core](https://github.com/yohanzytoon/IFT3913-tache3-tika/actions/runs/43999578020/job/133759997782) | 755 tests, 0 échec, 0 erreur, 5 ignorés; Checkstyle sans violation |
| Sondes comportementales facultatives | Non activées dans cette PR; 3 des 5 tests ignorés sont ces sondes |
| Téléversement des preuves | Réussi malgré l'échec du contrôle |
| Build complet et E2E | Ignorés; cette exécution ne prouve pas leur réussite |

[Artefact Semgrep de cette exécution](https://github.com/yohanzytoon/IFT3913-tache3-tika/actions/runs/43999578020/artifacts/14291726261). Les rapports locaux sont également versionnés pour éviter de dépendre de la durée de conservation des artefacts.

## Vérifications locales du 16 novembre 2026 (Montréal)

| Vérification | Résultat observé |
|---|---|
| Branche `main` sécurisée `abe046c26`, comparée à `tache3-clean` | 0 nouvelle alerte, sortie 0 |
| Branche `yohan` `f53c27dcb`, comparée à `tache3-clean` | 4 nouvelles alertes, 0 erreur, sortie 1 |
| Contrôle Python après durcissement des rapports invalides | 14 tests réussis |
| Vraies analyses Semgrep sur dépôt temporaire | 11 vérifications réussies |

Les onze vérifications utilisent le vrai script de contrôle et Semgrep 1.140.0 avec les mêmes règles, sur de petits fichiers Java synthétiques committés dans un dépôt jetable. Ce sont des tests du contrôle, pas des preuves supplémentaires d'exploitation dans Tika. Les commandes ci-dessous permettent de les reproduire; leurs rapports détaillés sont générés hors du dépôt et téléversés comme artefacts par la CI. Les copies des journaux de revue ne sont pas conservées dans l'arbre courant pour éviter les doublons. Les commits temporaires ne sont pas des commits publiés du projet.

Les preuves originales nécessaires à la comparaison des vulnérabilités restent versionnées : [scan complet avant](evidence/before-full/semgrep.json), [scan complet après](evidence/yohan-full/semgrep.json) et [nouvelles alertes](evidence/yohan-new/semgrep.json), avec leurs métadonnées et journaux.

| Scénario | Observation |
|---|---|
| Changement propre | Aucune nouvelle alerte, sortie 0 |
| Nouvelle alerte sur événement PR | Une nouvelle alerte, sortie 1 |
| Inventaire avant remplacement | Une alerte totale |
| Alerte existante inchangée et modification documentaire | Aucune nouvelle alerte, sortie 0 |
| Alerte existante déplacée de deux lignes | Aucune nouvelle alerte, sortie 0 |
| Ancienne alerte supprimée et nouvelle XXE ajoutée | Une nouvelle alerte, sortie 1 |
| Inventaire après remplacement | Toujours une alerte totale : le total seul aurait masqué le changement |
| Push de plusieurs commits, dont le dernier est inoffensif | La référence est bien `before`; une nouvelle alerte, sortie 1 |
| Premier push avec `before` nul | Référence de la branche par défaut; une nouvelle alerte, sortie 1 |
| Réparation complète comparée à la référence propre | Aucune nouvelle alerte, sortie 0 |
| Règle YAML invalide | Erreur d'analyse, sortie 2; jamais déclarée saine |

Les preuves comportementales Tika originales sont conservées dans [baseline-proofs.log](evidence/baseline-proofs.log) et [yohan-maven.log](evidence/yohan-maven.log). Ce dernier active les trois sondes : 755 tests, 0 échec, 0 erreur, 2 ignorés. Il ne faut pas confondre ce résultat local avec la PR, où les sondes sont désactivées. Maven n'a pas été relancé lors de cette revue, l'accès au cache local n'ayant pas été autorisé.

## Modifications issues de la revue et limites

- Le workflow exécute maintenant les onze vérifications réelles avant le contrôle du code Tika et conserve leurs rapports même en cas d'échec.
- Les rapports JSON de forme invalide sont classés comme erreurs d'outil et conservent des métadonnées de diagnostic.
- Le build complet hérité est rétabli automatiquement pour les pushes et PR lorsque `security` et `core-tests` réussissent; les E2E dépendent toujours de ce build. L'option manuelle `full_build` vaut désormais `true` par défaut. Une démonstration manuelle ciblée peut explicitement la désactiver.
- L'exécution distante liée ci-dessus précède ces modifications de revue. Aucun nouveau succès distant, build complet ou résultat E2E n'est revendiqué pour elles. Une nouvelle exécution après publication reste nécessaire.
- Un push ultérieur purement documentaire sur une branche déjà vulnérable peut passer le contrôle différentiel contre `before`. Cela signifie « aucune nouvelle alerte dans ce push », pas « aucune vulnérabilité ». Une PR vers `main` ou un lancement manuel avec `baseline=tache3-clean` conserve la comparaison cumulative.

## Reproduire la validation du scanner

Depuis la racine du dépôt, dans l'environnement Python où les dépendances épinglées sont installées :

```sh
python -m unittest discover -s scripts/tache3 -p 'test_*.py' -v
python scripts/tache3/validate_scanner.py --output /tmp/tache3-scanner-validation
```

Pour les scans et les sondes Tika, voir les commandes du [rapport](RAPPORT_YOHAN.md#reproduire). Les validations propres/réparées ci-dessus réussissent localement; une exécution GitHub verte du contrôle sur la référence propre reste à lier pour compléter la preuve distante du plan. Le rickroll et les sept types réunis restent dans le périmètre du binôme.
