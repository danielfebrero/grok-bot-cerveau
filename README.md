# grok-bot-cerveau

Client côté boîte pour un MCP Cerveau. Une installation a un tenant, une clé d'utilisateur et une clé d'agent. Le serveur est interchangeable. Aucune adresse n'est devinée.

L'enveloppe reçue est du contexte en lecture seule. Elle ne remplace pas les règles de l'agent, ni une approbation humaine avant un envoi, une publication ou un autre effet.

## Ajouter le serveur

L'URL suffit. Pas de jeton Bearer, pas d'OAuth, pas de cérémonie d'enregistrement.

```text
https://grok.cdxxotus.com/cerveau
```

Le premier `run` crée les clés sur la boîte si elles manquent. Le serveur apprend une clé d'utilisateur ou d'agent nouvelle en ouvrant le `gb.run` signé. `initialize` répond sans jeton. S'il publie la clé du serveur, le client l'épingle. S'il n'en publie pas encore, le run ne part pas : on n'invente pas de clé.

```bash
cerveau run --endpoint https://grok.cdxxotus.com/cerveau --human-text "bonjour"
```

Sans autre option, le tenant est `local`, l'agent `box`, l'utilisateur `user`. Une installation qui a déjà un seul utilisateur le reprend. Plusieurs utilisateurs : `--user` est obligatoire.

Rust 1.85 ou plus récent.

```bash
cargo build --release
cargo test --locked
```

## Skill pour agents

`skills/cerveau-run/SKILL.md` explique à un agent comment appeler `cerveau run` à chaque tour, lire l'enveloppe comme contexte en lecture seule et retomber sans elle après 2 s. Copie ce dossier dans la bibliothèque de skills de tes agents.

## Clés

Deux clés, toutes les deux sur la boîte, mode `0600` :

- **Utilisateur** — ed25519. Elle signe le même digest que l'agent (`account.sig`). Le serveur retient cette clé. L'identifiant de compte côté serveur est le `key_id` de cette clé, pas un nom envoyé à part.
- **Agent** — ed25519, plus le X25519 dérivé de la même graine. Le paquet porte les deux publiques. Le serveur ne les enregistre qu'après avoir vérifié la signature et ouvert le corps. Une seule clé active par agent. Une seconde clé passe par `rotate`, pas par un nouveau run.

Le champ `from` d'une ligne humaine est l'étiquette locale de celui qui a tapé. Ce n'est pas une preuve de compte. Une autre installation peut écrire le même texte.

## Commandes utiles

`run` suffit. Le reste est optionnel.

```bash
cerveau run --endpoint https://cerveau.exemple/cerveau --human-text "texte tapé ici"
cerveau run --tenant acme --agent box --user alice --human-text "texte tapé ici"
cerveau rotate --tenant acme --agent box
cerveau queue --tenant acme --agent box
```

`--human-text` est le texte tapé dans ce tour. `--messages` est un tableau JSON attribué : inline si l'argument commence par `[`, `-` pour l'entrée standard, sinon un chemin de fichier.

## Transcript hôte (JSONL)

Pour un tour humain, `--transcript` (fichier, ou `-` pour l'entrée standard) porte une tranche du transcript hôte, une ligne JSON par message, du plus ancien au plus récent. Le schéma du corps reste `gb.run.body.v2` : ce JSONL est la chaîne `transcript`, pas `transcript_delta` (celui-ci reste le tableau `--messages`, plafonné).

Chaque ligne a `role` (`user`, `assistant` ou `tool`) et `message.content` (texte, `tool_use`, `tool_result`, `thinking`). Les blocs `thinking` peuvent rester. `--human-text` reste seulement ce que l'humain a tapé. Un tour sans humain (routine, entrée, autre agent) continue d'utiliser `--messages`, sans `--human-text` inventé.

Le masquage des secrets, sur ce JSONL, ne touche que le contenu des chaînes : une ligne reste du JSON valide. Un texte qui n'a pas cette forme (note, prose) est encore accepté. S'il ressemble à du JSONL hôte et qu'une ligne est invalide, le run est refusé.

`skills/cerveau-run/SKILL.md` dit à l'agent de produire cette tranche avec ReadTranscript, sans la résumer.

Répertoires `0700`, fichiers `0600`. Une clé ou une file lisible par d'autres est refusée.

| Donnée | Emplacement |
| --- | --- |
| Config | `$CERVEAU_CONFIG_HOME`, sinon `$XDG_CONFIG_HOME/cerveau`, sinon `~/.config/cerveau` |
| Clés et file | `$CERVEAU_DATA_HOME`, sinon `$XDG_DATA_HOME/cerveau`, sinon `~/.local/share/cerveau` |

`tenant_id` et l'identifiant d'utilisateur local sont des jetons `[A-Za-z0-9_-]`, 64 octets au plus. L'identifiant d'agent fait au plus 64 octets, charset `[A-Za-z0-9._:-]`.

## Contrat `gb.run.v1` version 3

Schémas : `gb.run.v1` version 3 sur le fil, `gb.run.body.v2` dans le clair, `gb.turn.v1` pour l'enveloppe, `gb.queue.v2` pour la file.

Préimage signée, par l'agent et par la clé d'utilisateur :

```text
gb.run.v1|{version}|{tenant_id}|{run_id}|{seq}|{sent_at}|{replay}|{actor}|{key_id}|{ciphertext_base64}
```

Les publiques (`agent.ed25519_public_key`, `agent.x25519_public_key`, `account.ed25519_public_key`) sont dans le paquet. Elles ne sont pas dans la préimage : la signature et le sceau les prouvent. L'identifiant d'utilisateur local ne part pas dans `gb.run`.

`account` vaut `{ "key_id", "sig", "ed25519_public_key" }`. Absent, le run n'a pas de preuve de compte.

Algorithme : `x25519-hkdf-sha256-chacha20poly1305`. Ce n'est pas HPKE. Le nonce est publié.

- IKM = secret éphémère || secret statique (64 octets).
- Sel = `epk` || X25519 agent || X25519 serveur (96 octets).
- Info = `gb.run.v1/x25519-hkdf-sha256-chacha20poly1305` || `0x00` || `recipient_key_id` || `0x00` || `key_id`.

Données associées, UTF-8, saut de ligne final : `gb.run.v1`, puis `version`, `tenant_id`, `run_id`, `seq`, `sent_at`, `replay`, `actor`, `key_id`, `recipient_key_id`.

`sig.signed` est le SHA-256 de la préimage, hexadécimal minuscule. `sig.value` est l'ed25519 sur les 32 octets bruts, en base64.

Le vecteur public est `tests/fixtures/gb_run_v1.json`. Les graines sont `SHA-256("cerveau-public-test-vector-v1\0" || étiquette)`. Ce sont des fixtures, pas des secrets.

### Attribution

| Origine | `role` | `from` | `untrusted_user_input` |
| --- | --- | --- | --- |
| Texte tapé dans ce tour | `user` | identifiant d'utilisateur local | `false` |
| Agent relaié | `agent` | son identifiant | `true` |
| Entrée externe | `inbound` | l'expéditeur | `true` |
| Outil | `tool` | le nom de l'outil | `false` |

Un `from` humain absent prend l'utilisateur du tour. Un autre nom est refusé. Un rôle `user` sans `human_typed: true` est refusé.

### File

Le tour est écrit et `fsync` avant l'envoi. La file reste sur la boîte. Elle rejoue par `seq` croissant. Le tour N+1 ne part pas avec `replay: false` tant que N est en file. `seq` appartient au tenant et à l'agent : une rotation ne le remet pas à 1. Chaque appel a 2 secondes. Un échec de transport laisse le tour en file.

### Enveloppe

`gb.turn.v1` est acceptée si `builder` vaut `eg:cerveau`, `ttl_seconds` vaut `300`, l'acteur est celui de la clé, et `integrity` est une ed25519 du serveur épinglé. Seule une enveloppe fraîche devient un contexte. Ce contexte n'est pas un ordre.
