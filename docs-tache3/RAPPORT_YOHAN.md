# Tâche 3 — travail de Yohan Zytoon

Cette partie couvre la préparation du dépôt, le contrôle Semgrep du workflow, sa validation et trois vulnérabilités documentées. Elle ne constitue pas encore la remise complète du binôme : les quatre autres types, la comparaison finale des sept types et le rickroll appartiennent à la partie de Zouhair.

## État de référence et reproductibilité

Le dépôt conserve l'historique du cas d'étude Tika. Source : commit `526f3a09dd596d5456d4dd079804aba7a57e6af5` de notre [dépôt Tâche 2](https://github.com/yohanzytoon/IFT3913-tache2-tika/commit/526f3a09dd596d5456d4dd079804aba7a57e6af5). La branche `main` garde le code sécurisé. La branche `yohan` contient les modifications délibérément vulnérables. Le tag `tache3-clean`, SHA `98cef731437f2499dafec8d6190c2d10c88d11e4`, conserve le code sécurisé, le workflow, les règles et les trois sondes.

Environnement local vérifié : macOS arm64, OpenJDK 17.0.18, Maven 3.10.0, Python 3.11, Semgrep 1.140.0. Le fichier [requirements.txt](../.semgrep/requirements.txt) fixe également les dépendances Python : la résolution initiale choisissait Pydantic 2.14.3, incompatible avec le composant MCP de cette version de Semgrep; Pydantic 2.11.9 a été testé avec succès. `pip check` ne signale aucune incompatibilité.

Les trois règles existantes sont copiées sans modification depuis le commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` de `semgrep/semgrep-rules`, avec leur licence et leurs chemins d'origine dans [.semgrep/README.md](../.semgrep/README.md). Aucun motif spécifique à nos noms de classes ou commentaires n'a été inventé pour provoquer une alerte.

## Workflow et décisions de conception

Le workflow existant [main-jdk17-build.yml](../.github/workflows/main-jdk17-build.yml) est modifié. Le job `security` est obligatoire et son échec rend le workflow rouge. Le job `core-tests` exécute la suite du module modifié. Le build complet hérité dépend des deux jobs et s'exécute automatiquement sur les pushes et PR lorsqu'ils réussissent. L'option manuelle `full_build`, activée par défaut, permet de le désactiver explicitement pour une démonstration ciblée. Le build complet dépend de services externes et n'est pas assimilé aux tests de `tika-core` validés ici. Les E2E dépendent du build complet.

Les déclencheurs couvrent les PR vers `main`, les pushes sur `main`, `yohan`, `zouhair/**`, `validation/**`, ainsi qu'un lancement manuel. Il n'y a pas d'exclusion des changements de documentation qui masquerait un résultat de contrôle requis. Le checkout utilise le SHA de tête réel des PR et récupère tout l'historique.

Le script [security_gate.py](../scripts/tache3/security_gate.py) choisit la référence ainsi :

- PR : ancêtre commun entre la tête et le SHA de la branche cible fourni par l'événement.
- Push ordinaire : `before`, afin d'inclure tous les commits poussés ensemble.
- Premier push de branche : ancêtre commun avec la branche par défaut, ou SHA source enregistré si cette comparaison serait vide/impossible.
- Exécution manuelle/locale : SHA fourni, sinon SHA source enregistré.

Une référence absente, non ancêtre ou égale à la tête provoque un échec explicite. Le scan exige un checkout sans modifications suivies non committées. La stratégie refuse les force-pushes sans ancêtre valide au lieu de déclarer le code sûr.

L'analyse couvre les sources Java de production des cinq modules permis : core, serialization, OCR, PDF et Microsoft. Les sondes de test ne sont pas comptées comme vulnérabilités. Le même jeu de règles versionné et le même moteur servent aux scans complets et différentiels. Les trois règles actuelles concernent notre partie; le jeu devra être étendu pour les types de Zouhair.

Le scan différentiel utilise `--baseline-commit`, `--error`, `--strict`, `--disable-nosem` et `--no-rewrite-rule-ids`. Les résultats WARNING bloquent autant que les ERROR. Code de sortie du contrôle : `0` pour absence de nouvelle alerte; `1` pour nouvelles alertes; `2` pour erreur d'outil, rapport invalide ou analyse partielle avec erreurs. Le JSON est vérifié même si le processus renvoie zéro. Aucun `continue-on-error` ni `|| true` ne transforme le contrôle en succès.

Les artefacts sont téléversés avec `if: always()`. Ils contiennent le JSON, le journal et des métadonnées : SHA avant/après, version, empreintes SHA-256 des règles, portée, commande, compte des résultats et codes de sortie. Une erreur avant le démarrage du scanner reste rouge; l'absence d'artefact n'est pas présentée comme une analyse réussie.

## V1 — entités XML externes, CWE-611

**Emplacement :** `tika-core/src/main/java/org/apache/tika/utils/XMLReaderUtils.java`, méthode publique `getDocumentBuilderFactory()`. [Commit](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/8074ea48a).

Cette fabrique constitue un point central de configuration des parseurs DOM. Initialement, elle désactive l'expansion des références et les entités externes. La modification active l'expansion, appelle `setFeature("http://xml.org/sax/features/external-general-entities", true)` et autorise le protocole `file` avec `ACCESS_EXTERNAL_DTD`.

Un document XML contrôlé par un appelant peut alors référencer un fichier local par une entité externe; le contenu apparaît dans le DOM construit directement depuis cette fabrique. La sonde crée uniquement un fichier temporaire contenant `TACHE3_LOCAL_MARKER` : le DOM sécurisé ne contient pas ce marqueur, tandis que le DOM modifié le contient.

**Limite importante :** `getDocumentBuilder()` ajoute encore un résolveur qui ignore les entités. Nous ne prétendons pas que tous les chemins Tika deviennent vulnérables. La preuve concerne précisément la fabrique publique utilisée sans ce résolveur. Les limites d'expansion restent en place et le protocole autorisé est `file`, pas l'ensemble des protocoles réseau.

**Semgrep :** règle `documentbuilderfactory-external-general-entities-true`, une nouvelle alerte à la ligne 266 dans la version analysée. **Correction :** rétablir la configuration de la référence (`setExpandEntityReferences(false)`, entités générales désactivées, aucune autorisation de DTD externes).

## V2 — validation des certificats TLS désactivée, CWE-295

**Emplacement :** `tika-core/src/main/java/org/apache/tika/io/TikaInputStream.java`, méthode `get(URL, Metadata)`. [Commit](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/0031d817b).

Cette méthode charge réellement les documents fournis par URL. Le code original utilise la validation HTTPS du JDK. La modification installe sur la connexion un `SSLContext` avec un `X509TrustManager` dont les méthodes `checkClientTrusted` et `checkServerTrusted` sont vides. Le gestionnaire est utilisé, et non simplement déclaré dans du code mort.

La sonde génère une clé/certificat éphémère avec `keytool`, lance un serveur HTTPS lié exclusivement à `127.0.0.1`, et lit un marqueur inoffensif. Le certificat n'appartient à aucune autorité de confiance mais possède le bon nom d'hôte : la référence rejette la connexion, la version vulnérable accepte le document. La vérification du nom d'hôte n'est pas supprimée; l'attaque contourne la confiance dans la chaîne de certification et permet une interception avec un certificat non fiable correspondant au nom attendu.

**Semgrep :** règle `insecure-trust-manager`, deux nouvelles alertes aux lignes 228–230 et 232–234. Elles représentent **un seul type de vulnérabilité**, pas deux. **Correction :** supprimer le gestionnaire permissif et utiliser le magasin de confiance du JDK ou un magasin explicitement administré.

## V3 — permissions par défaut excessives, CWE-276

**Emplacement :** `tika-core/src/main/java/org/apache/tika/io/TemporaryResources.java`, méthode `createTempFile(String)`. [Commit](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/f2de58f8d).

Cette classe gère les fichiers temporaires contenant les documents extraits. Après la création normale du fichier, la modification applique `rw-rw-rw-` sur un système POSIX. Elle accorde la lecture et l'écriture au groupe et aux autres utilisateurs, alors que le fichier temporaire de référence est réservé au propriétaire dans l'environnement testé.

La sonde écrit un document synthétique, lit les permissions effectives et vérifie `OTHERS_READ` et `OTHERS_WRITE`. Ces permissions sont absentes avant et présentes après. La suppression normale à la fermeture fonctionne toujours : elle ne supprime pas le risque d'accès pendant la durée de vie du fichier. L'accès effectif dépend aussi des permissions des répertoires parents; la sonde prouve les bits de permission, sans prétendre avoir exécuté un processus sous un autre compte.

**Semgrep :** règle `overly-permissive-file-permission`, une nouvelle alerte à la ligne 94. La règle utilise CWE-276; CWE-732 est une catégorie plus générale apparentée, et n'est pas comptée comme un quatrième type. **Correction :** supprimer l'élargissement des permissions ou limiter explicitement le fichier à `rw-------`. Le comportement introduit est limité aux systèmes POSIX; Windows reste inchangé.

## Validation locale obtenue

| Vérification | Résultat observé |
|---|---|
| Suite core sur la source sécurisée | 752 tests, 0 échec, 0 erreur, 2 ignorés |
| Trois sondes sur la référence sécurisée | 3 tests, 0 échec, 0 erreur |
| Suite core avec les trois sondes, version vulnérable | 755 tests, 0 échec, 0 erreur, 2 ignorés; Checkstyle validé |
| Tests unitaires du contrôle CI | 14 réussis après revue : baseline PR, push multiple, nouvelle branche, référence invalide, rapports malformés et gestion des résultats/erreurs |
| Validation réelle du scanner après revue | 11 vérifications réussies sur fixtures Java isolées, dont déplacement, remplacement à total constant, réparation et règle invalide; détails dans VALIDATION.md |
| Scan complet avant | 682 fichiers, 3 règles, 0 alerte, 0 erreur |
| Scan complet après les trois changements | 4 alertes correspondant à 3 types, 0 erreur |
| Contrôle différentiel après les trois changements | 4 nouvelles alertes, sortie 1 : échec attendu |

Les preuves brutes sont conservées dans [evidence](evidence/). Le rapport final avant/après des **sept** types sera complété avec la partie de Zouhair. Les exécutions GitHub Actions et les validations supplémentaires sont consignées dans [VALIDATION.md](VALIDATION.md).

## Reproduire

Créer un environnement Python 3.11 et installer `python -m pip install -r .semgrep/requirements.txt`. Activer cet environnement afin que `python` et `semgrep` utilisent le même répertoire d'installation.

```sh
# Contrôle normal : 0 sur main, 1 sur la branche vulnérable.
python scripts/tache3/security_gate.py --baseline tache3-clean --output /tmp/tache3-gate

# Inventaire complet : les alertes sont enregistrées sans rendre l'inventaire rouge.
python scripts/tache3/security_gate.py --full --output /tmp/tache3-inventory

# Contrôle de la logique CI.
python -m unittest discover -s scripts/tache3 -p 'test_*.py' -v

# Référence sécurisée, avec les sondes activées explicitement.
git switch main
mvn -B -pl tika-core -am -Dtest=Tache3SecurityProofTest \
  -Dsurefire.failIfNoSpecifiedTests=false -Dtache3.demo=true test

# Branche de démonstration : trois comportements vulnérables attendus.
git switch yohan
mvn -B -pl tika-core -am -Dtache3.demo=true -Dtache3.expectVulnerable=true test
```

Les sondes sont désactivées dans les exécutions ordinaires : elles caractérisent volontairement un comportement sûr ou vulnérable selon la révision, et ne constituent pas des assertions de sécurité à conserver telles quelles en production. Le contrôle Semgrep reste indépendant et rouge sur l'introduction des vulnérabilités, même lorsque les sondes passent.

## Références et utilisation de l'IA

- [Consignes et critères de la tâche](https://github.com/umontreal-diro/IFT3913/blob/2026/tache3/readme.md)
- [CLI Semgrep : analyse différentielle et codes de sortie](https://semgrep.dev/docs/cli-reference)
- [Sources et licence des règles](../.semgrep/README.md)
- [Code des sondes](../tika-core/src/test/java/org/apache/tika/security/Tache3SecurityProofTest.java)

Codex a aidé à préparer le dépôt, écrire le workflow et son script, choisir et introduire les trois modifications pédagogiques, construire les sondes, exécuter les validations et rédiger cette documentation. Les résultats indiqués proviennent des rapports conservés, et non de résultats supposés. Yohan doit relire les modifications et être capable d'en expliquer le fonctionnement; cette phrase ne prétend pas que cette relecture humaine a déjà eu lieu.
