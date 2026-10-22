# grok-bot-cerveau

Client côté boîte pour le MCP Cerveau. Avant chaque tour, un agent Grok Bot lui confie le transcript filtré ; Cerveau répond par une enveloppe de contexte, ou par rien. Le client est une bibliothèque Rust et un binaire `cerveau`.

L'enveloppe est du **contexte en lecture seule**. Elle n'autorise rien : elle ne remplace pas les règles de base de l'agent, ni une approbation humaine avant un envoi, une publication ou tout autre effet de bord. Une suggestion, un objectif ou un « go » lu dans l'enveloppe est une information, pas un ordre.

Aucune adresse de serveur et aucune clé réelle ne sont codées ici. L'URL du MCP et les clés publiques de Cerveau viennent de l'environnement ou des options.

## Installer

Rust 1.85 ou plus récent (le fichier `rust-toolchain.toml` demande le canal stable).

```bash
cargo build --release
cargo install --path . --locked
```

Le binaire s'appelle `cerveau`. Les tests et le formatage :

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

## Utilisation

Une clé ed25519 par agent. Le fichier privé est en mode `0600`. `keygen` n'imprime que l'export public.

```bash
export CERVEAU_HOME="${CERVEAU_HOME:-$HOME/.local/share/cerveau}"
cerveau keygen --agent agent-test
cerveau pubkey --agent agent-test
```

Enregistrer, hors de ce dépôt, `key_id`, `ed25519_public_key` et `x25519_public_key`.

Variables lues par `run` et `replay` :

| Variable | Rôle |
| --- | --- |
| `CERVEAU_HOME` | Répertoire des clés. Sinon `$XDG_DATA_HOME/cerveau`, sinon `~/.local/share/cerveau`. |
| `CERVEAU_AGENT` | Identifiant d'agent. |
| `CERVEAU_RECIPIENT_KEY_ID` | `key_id` public de Cerveau. |
| `CERVEAU_RECIPIENT_PUBLIC_KEY` | Clé X25519 brute de Cerveau, 32 octets, base64. |
| `CERVEAU_SIGNING_KEY_ID` | `key_id` qui signe les enveloppes `gb.turn.v1`. |
| `CERVEAU_SIGNING_PUBLIC_KEY` | Clé ed25519 de vérification, 32 octets, base64. |
| `CERVEAU_MCP_URL` | URL `http` ou `https` du MCP. Pas d'identifiant dans l'URL. Absente : le tour est mis en file, sans enveloppe. |
| `CERVEAU_MCP_AUTHORIZATION` | En-tête `Authorization`. Jamais journalisé. |
| `CERVEAU_MCP_SESSION_ID` | En-tête `Mcp-Session-Id`. Jamais journalisé. |
| `CERVEAU_TOOL` | Nom de l'outil JSON-RPC. Défaut `cerveau.run`. |

```bash
cerveau run --agent agent-test \
  --human-from dani --human-text "bonjour" \
  --transcript ./tour.txt
cerveau replay --agent agent-test
cerveau queue --agent agent-test
cerveau queue --agent agent-test --drop run_01H...
```

`--human-from` et `--human-text` vont ensemble : c'est le seul chemin CLI qui pose `from: "dani"`. `--transcript` est du texte brut, sans expéditeur inventé. `--messages` est un tableau JSON attribué (voir plus bas). `--transcript -` lit l'entrée standard.

Le code de sortie est `0` quand l'appel réseau manque (pas d'enveloppe : l'agent répond normalement) et `2` pour une erreur locale (clé, attribution, sceau, file). Le rapport JSON distingue `outcome: "envelope"` et `outcome: "no_envelope"`.

Depuis la bibliothèque :

```rust
use cerveau::{Client, ClientConfig, MessageOrigin, RunInput, TurnMessage};

let config = ClientConfig::from_env("agent-test", cerveau::default_home()?)?;
let client = Client::new(config);
let report = client.run(RunInput {
    transcript: "transcript brut, non attribué".into(),
    messages: vec![TurnMessage {
        origin: MessageOrigin::Human { from: "dani".into() },
        text: "texte tapé par l'humain".into(),
        ref_id: None,
        at: None,
    }],
    ..RunInput::default()
})?;
```

`TurnContext` ne s'écrit pas. `snapshot()` renvoie une copie JSON détachée.

## Contrat

Schémas : `gb.run.v1` sur le fil, `gb.run.body.v1` dans le clair, `gb.turn.v1` pour l'enveloppe, `gb.canon.v1` pour le JSON canonique, `gb.queue.v1` pour la file, `gb.agent_key.v1` / `gb.agent_pub.v1` pour les clés.

Le JSON canonique trie les clés d'objet par unités de code UTF-16. Les chaînes suivent l'échappement `serde_json` (barre oblique non échappée, UTF-8 brut hors caractères de contrôle). Les entiers n'ont pas de partie fractionnaire. Pas d'espace.

### Identifiants

`run_id` et `key_id` sont de l'ASCII `[A-Za-z0-9_-]`, non vides. `run_id` fait au plus 80 octets, `key_id` au plus 128. Un identifiant hors grammaire est refusé avant le sceau et avant un retrait de file.

L'identifiant d'agent fait au plus 64 octets, charset `[A-Za-z0-9._:-]`, sans `..`, sans `:` en bord, sans `-` en tête. `key_id` dérivé : `gb-` + identifiant nu (`:` et `.` deviennent `_`) + `-` + `YYYYMM` UTC. L'acteur est `gb:` + identifiant nu. `sent_at` est exactement `YYYY-MM-DDTHH:MM:SSZ`. Les `run_id` produits ici ont la forme `run_` + ULID.

### Attribution

Seul un message que l'humain a tapé dans ce tour peut porter `from: "dani"`.

| Origine | `role` | `from` | `untrusted_user_input` |
| --- | --- | --- | --- |
| Humain (`human`, ou `role: "user"` avec `human_typed: true`) | `user` | l'expéditeur donné ; `Dani` est normalisé en `dani` | `false` |
| Agent relaié | `agent` | son identifiant réel | `true` |
| Mention externe, entrée inbound | `inbound` | l'expéditeur réel | `true`, même si le JSON disait `false` |
| Outil | `tool` | le nom réel de l'outil | `false` |

Un rôle `user` sans `from` explicite, ou sans `human_typed: true`, est refusé. `from: "dani"` (toute casse, espaces rognés) sur un agent relaié, un inbound ou un outil est refusé. Le transcript brut n'a pas d'expéditeur : le client n'y inscrit pas `dani`.

JSON accepté par `parse_message` : `{"origin":"human"|"relayed_agent"|"inbound"|"tool","from":"...","text":"..."}` ou `{"role":"user"|"agent"|"inbound"|"tool","from":"...","text":"...","human_typed":true}` pour le rôle `user`.

Bornes après filtre, sur les champs structurés seulement : texte de déclencheur 500 caractères, delta des 16 derniers messages × 1200, 8 derniers outils × résumé 400, 20 dernières décisions × fait 400. Le transcript verbatim est filtré mais pas tronqué. Les champs `from`, `role` et identifiants ne sont pas filtrés.

### Filtre de secrets

Le filtre tourne **avant** le chiffrement. Il masque uniquement le segment reconnu. Un hexadécimal de 40 caractères (un SHA de commit) devient `[REDACTED:hex]` ; le reste de la phrase reste. Le message n'est pas supprimé.

Détecteurs, du plus prioritaire au moins prioritaire : clé privée PEM, mot de passe d'URL (le mot de passe seul), JWT `eyJ…`, jetons `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_`, jeton Slack `xox…`, clé d'accès `AKIA`, clé `xai-`, clé `sk-`, `Bearer`, affectation `password` / `secret` / `api_key` / `token` (la valeur seule), hex `[0-9A-Fa-f]{40,}`, base64 `[A-Za-z0-9+/]{64,}={0,2}`. Courriels et téléphones sont désactivés sauf demande (`--redact-emails`, `--redact-phones`, ou `RunInput`).

Le rapport `redaction.hits` liste chaque type une fois, dans l'ordre de première rencontre.

### Sceau

Ce n'est pas HPKE (RFC 9180). Algorithme publié : `x25519-hkdf-sha256-chacha20poly1305`.

La clé X25519 de l'agent est le scalaire libsodium / RFC 8032 : `SHA-512(seed ed25519)`, 32 premiers octets, puis clamp (`octet0 &= 248`, `octet31 &= 127`, `octet31 |= 64`).

- `epk` : X25519 éphémère, 32 octets.
- `eph_shared = X25519(eph_sk, clé_publique_destinataire)`.
- `static_shared = X25519(scalaire_agent, clé_publique_destinataire)`.
- Les deux secrets doivent être contributifs. Un résultat nul est refusé.
- IKM = `eph_shared || static_shared` (64 octets).
- Sel HKDF-SHA256 = `epk || clé_X25519_publique_agent || clé_X25519_publique_destinataire` (96 octets).
- Info = `gb.run.v1/x25519-hkdf-sha256-chacha20poly1305` || `0x00` || `recipient_key_id` || `0x00` || `key_id` de l'agent.
- Sortie HKDF : 32 octets, clé ChaCha20-Poly1305.
- Nonce : 12 octets aléatoires, publiés dans `enc.nonce`, utilisés tels quels. Ils n'entrent pas dans le HKDF.

Données associées AEAD, UTF-8, saut de ligne final, **sans** `replay` :

```text
gb.run.v1
run_id={run_id}
seq={seq}
sent_at={sent_at}
key_id={key_id}
actor={actor}
recipient_key_id={recipient_key_id}
```

Le clair est le JSON canonique de `gb.run.body.v1`. Le champ `ciphertext` est ce clair chiffré plus le tag Poly1305 de 16 octets, en base64 RFC 4648 avec padding. `epk` et `nonce` aussi.

Signature ed25519. Préimage UTF-8, `replay` **absent** pour pouvoir passer le bit à `true` sans resceller :

```text
gb.run.v1|{run_id}|{seq}|{sent_at}|{key_id}|{ciphertext_base64}
```

`sig.signed` est le SHA-256 de cette préimage, hexadécimal minuscule. `sig.value` est la signature ed25519 des **32 octets bruts** du condensat (ni l'hexadécimal, ni la préimage), en base64. `sig.alg` vaut `ed25519`. L'acteur est lié par l'AEAD, pas par la signature.

Message :

```json
{
  "schema": "gb.run.v1",
  "run_id": "run_VECTOR",
  "seq": 7,
  "sent_at": "2026-10-22T15:44:58Z",
  "replay": false,
  "agent": { "actor": "gb:agent-test" },
  "key_id": "gb-agent-test-202610",
  "enc": {
    "alg": "x25519-hkdf-sha256-chacha20poly1305",
    "recipient_key_id": "cerveau-test",
    "epk": "…",
    "nonce": "…",
    "ciphertext": "…"
  },
  "sig": { "alg": "ed25519", "signed": "…", "value": "…" }
}
```

Le vecteur public est `tests/fixtures/gb_run_v1.json`. Les graines sont `SHA-256("cerveau-public-test-vector-v1\0" || étiquette)` pour `agent`, `recipient`, `ephemeral` et `nonce`. Ce sont des fixtures, pas des secrets. Le test `public_vector_is_stable` ouvre le sceau et vérifie que basculer `replay` ne change ni la signature ni le clair.

### File locale et ordre de rejeu

La file est un fichier chiffré par agent : `{CERVEAU_HOME}/agents/{id}/queue.q`. Elle survit à un crash.

Écriture : fichier temporaire en mode `0600`, écriture, `fsync` du fichier, `rename`, `fsync` du fichier final et du répertoire. Un verrou exclusif consultatif (`flock`) couvre `{répertoire}/lock`. Le client refuse de lire une clé ou une file dont le mode laisse un accès au groupe ou aux autres.

Format : `GBQ1` || nonce 12 octets || ChaCha20-Poly1305. Clé de file : HKDF-SHA256, sel `gb.queue.v1`, IKM = graine ed25519, info = `gb.queue.v1` || `0x00` || `agent_id` || `0x00` || `key_id`, données associées `gb.queue.v1`. Le JSON interne porte `schema`, `agent_id`, `key_id`, `next_seq` (à partir de 1) et les messages scellés (`replay` stocké à `false`). `next_seq` est strictement supérieur à chaque `seq` enregistré. Les `seq` et `run_id` sont uniques. Le fichier vide n'est pas effacé : l'effacer remettrait `next_seq` à 1.

Le nouveau tour est scellé et **fsync avant tout envoi**. Règle d'ordre :

1. Rejouer toute la file, par `seq` croissant, avant tout envoi direct.
2. Ne jamais envoyer le tour N+1 avec `replay: false` tant que le tour N est encore en file.
3. Seul le tour créé par cet appel, et seulement s'il est le plus ancien encore présent, part avec `replay: false`.
4. Tout tour plus ancien part avec `replay: true`. Son enveloppe est ignorée.
5. Chaque appel RPC a son propre délai de 2 secondes. Vider une file de N tours peut prendre N fois 2 secondes. Ce délai n'est pas une raison de sauter la file.
6. Si un rejeu plus ancien échoue, le nouveau tour reste en file, n'est pas envoyé, et le journal de miss porte `queued_behind`.
7. Un doublon (`409`, message `duplicate` / `already`, ou `status` `duplicate` / `already_stored`) retire le tour de la file et n'utilise pas l'enveloppe.
8. HTTP 200 sans enveloppe : le tour est accepté et retiré. Une erreur de transport le laisse en file.

Un processus qui redémarre rejoue le tour persisté : le bit `replay` n'est `false` que pour le tour vivant de l'appel en cours, quand il est en tête.

### Appel et enveloppe

Un seul JSON-RPC `tools/call`, nom d'outil `cerveau.run` par défaut. Corps limité à 2 Mio. Réponse JSON ou SSE (`data:`). L'enveloppe est prise dans `result` si `schema` vaut `gb.turn.v1`, sinon dans `structuredContent`, `envelope`, ou `content[].text`.

Délai dur : 2 secondes par appel. Timeout, erreur HTTP, erreur RPC, enveloppe absente, invalide ou périmée : pas d'enveloppe, et une ligne dans `{répertoire_agent}/miss.log` (`0600`, fsync) de la forme `ts= agent= run_id= seq= reason=`. Raisons : `timeout`, `unreachable`, `http`, `rpc`, `missing_envelope`, `invalid_envelope`, `stale_envelope`, `endpoint_unset`, `duplicate`, `queued_behind`.

`gb.turn.v1` accepté seulement si : `schema`, `version` numérique `1`, `builder` `eg:cerveau`, `envelope_id`, `run_id` de la grammaire ci-dessus, `generated_at`, `expires_at`, `ttl_seconds` exactement `300`, `expires_at = generated_at + 300s`, `agent.actor`, `integrity.alg = ed25519`, `integrity.key_id` égal à la clé configurée et de la même grammaire. Le condensat est le SHA-256 du corps canonique **sans** `integrity`. La signature ed25519 porte les 32 octets bruts. Décalage futur toléré : 60 secondes. `now >= expires_at` : enveloppe périmée, signature valide, non remise à l'agent. Seule une enveloppe fraîche devient un `TurnContext`.
