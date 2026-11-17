# Règles Semgrep

Version du moteur : `1.140.0` (Python 3.11).

Les règles sont des copies non modifiées de [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules/tree/a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2), commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`.
La licence originale est conservée dans `rules/LICENSE`.

| Fichier | Chemin original |
|---|---|
| insecure-trust-manager.yaml | java/lang/security/audit/crypto/ssl/insecure-trust-manager.yaml |
| overly-permissive-file-permission.yaml | java/lang/security/audit/overly-permissive-file-permission.yaml |
| documentbuilderfactory-external-general-entities-true.yaml | java/lang/security/audit/xxe/documentbuilderfactory-external-general-entities-true.yaml |

Ce jeu sera complété pour les quatre types de Zouhair. Le workflow charge tous les fichiers YAML de `rules/`. Les avertissements de sécurité bloquent aussi : aucun filtre de sévérité ne masque les règles WARNING.

Les sources Java de production des cinq modules autorisés sont analysées. Les tests de démonstration ne sont pas inclus dans les résultats : ils ne sont pas les vulnérabilités remises.

`baseline.txt` contient le SHA source immuable, utilisé pour les démonstrations manuelles et les premiers pushes sans référence exploitable. Les PR utilisent leur merge-base; les pushes ordinaires utilisent le SHA `before` de l'événement.
