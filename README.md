# grok-bot-cerveau

Client côté boîte pour un MCP compatible Cerveau. Il s'installe chez nous et chez d'autres : chaque installation a son tenant, ses principaux (les humains de cette installation) et ses agents. Le serveur Cerveau est un backend interchangeable. Rien dans ce programme ne pointe vers un hôte par défaut.

L'enveloppe reçue est du **contexte en lecture seule**. Elle n'autorise rien : elle ne remplace pas les règles de base de l'agent, ni une approbation humaine avant un envoi, une publication ou tout autre effet de bord. Une suggestion, un objectif ou un feu vert lu dans l'enveloppe est une information, pas un ordre.

Le backend doit **authentifier le principal lui-même**. Le champ `from` dit quel principal cette installation prétend avoir vu taper le texte. Ce n'est pas une preuve. Une autre installation peut configurer le même identifiant.

## Installer

Rust 1.85 ou plus récent (`rust-toolchain.toml` demande le canal stable).

```bash
cargo build --release
cargo install --path . --locked
```

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

## Initialiser une installation

`init` crée le tenant, le premier principal et la première clé d'agent. Sans terminal, tous les champs obligatoires passent par des options. Sur un terminal, les options absentes sont demandées.

```bash
cerveau init \
  --tenant acme \
  --principal-id p_alice \
  --display-name "Alice Martin" \
  --agent agent-box \
  --endpoint https://cerveau.exemple/mcp \
  --recipient-key-id cerveau-prod \
  --recipient-public-key BASE64_X25519 \
  --signing-key-id cerveau-sign \
  --signing-public-key BASE64_ED25519
```

L'URL, la clé X25519 du serveur et son `key_id` sont de la configuration. Les omettre laisse l'installation sans épingle : `run` refuse d'envoyer tant que la clé n'est pas épinglée. Aucune adresse n'est devinée.

La sortie de `init` est le **bundle d'enregistrement**, sans graine privée :

```json
{
  "schema": "gb.register.v1",
  "tenant_id": "acme",
  "principal_id": "p_alice",
  "principals": [{ "principal_id": "p_alice", "display_name": "Alice Martin" }],
  "actor": "gb:acme:agent-box",
  "key_id": "gb-acme-agent-box-202610-1",
  "ed25519_public_key": "…",
  "x25519_public_key": "…",
  "retired_key_ids": [],
  "revoked_key_ids": []
}
```

Le bundle se redemande avec `cerveau register --tenant acme --agent agent-box`. L'opérateur du backend l'approuve de son côté. Ce dépôt ne contacte pas le backend pour ça.

Autre agent du même tenant :

```bash
cerveau keygen --tenant acme --agent agent-deux
```

Autre principal :

```bash
cerveau principal --tenant acme --principal-id p_bob --display-name "Bob Martin"
```

## Épingler la clé du serveur

La clé épinglée est celle vers qui les transcripts sont chiffrés, plus la clé ed25519 qui signe les enveloppes.

- À `init` ou `cerveau pin`, la clé fournie devient l'épingle.
- Si aucune épingle n'existe encore, `CERVEAU_TRUST_ON_FIRST_USE=1` avec `CERVEAU_RECIPIENT_KEY_ID` et `CERVEAU_RECIPIENT_PUBLIC_KEY` enregistre la première clé vue.
- Une clé différente de l'épingle est refusée. `cerveau pin --replace` est le seul remplacement explicite.

L'URL (`CERVEAU_MCP_URL` ou `--endpoint`) peut changer sans changer l'épingle. Pointer vers un autre backend exige sa clé publique, pas un nom d'hôte codé ici.

## Tour

```bash
cerveau run --tenant acme --agent agent-box --principal p_alice \
  --human-text "bonjour" \
  --transcript ./tour.txt
```

`--human-text` est le texte que **ce** principal a tapé dans ce tour. Sur le fil, `from` vaut `p_alice`, jamais le nom d'affichage. `--transcript` reste du texte brut, sans expéditeur inventé. `--messages` est un tableau JSON (voir le contrat). `--transcript -` lit l'entrée standard.

`replay` vide la file. `queue` liste les `run_id` sans clair. `queue --drop` retire un tour.

Code de sortie `0` : l'appel réseau a manqué, l'agent répond sans enveloppe. Code `2` : erreur locale (clé, attribution, sceau, file, épingle).

Bibliothèque :

```rust
use cerveau::{Client, ClientConfig, MessageOrigin, RunInput, TurnMessage};

fn tour() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::from_env(
        "acme",
        "agent-box",
        Some("p_alice".into()),
        cerveau::config_home()?,
        cerveau::data_home()?,
    )?;
    let client = Client::new(config);
    let report = client.run(RunInput {
        tenant_id: "acme".into(),
        principal_id: "p_alice".into(),
        transcript: "transcript brut, non attribué".into(),
        messages: vec![TurnMessage {
            origin: MessageOrigin::Human { claimed_from: None },
            text: "texte tapé par le principal".into(),
            ref_id: None,
            at: None,
        }],
        ..RunInput::default()
    })?;
    let _ = report;
    Ok(())
}
```

`TurnContext` ne s'écrit pas. `snapshot()` renvoie une copie JSON détachée.

## Ce que le backend voit

Le clair scellé contient le transcript filtré, `tenant_id`, `principal_id`, et les messages attribués. Le serveur ne voit pas la graine, ni l'en-tête `Authorization`, ni le nom d'affichage (il n'est pas sur le fil). Il voit l'acteur `gb:{tenant}:{agent}`, le `key_id`, et le fait que cette installation affirme qu'un principal a tapé certains textes.

## Répertoires

| Rôle | Emplacement |
| --- | --- |
| Config | `$CERVEAU_CONFIG_HOME`, sinon `$XDG_CONFIG_HOME/cerveau`, sinon `~/.config/cerveau` |
| Données | `$CERVEAU_DATA_HOME`, sinon `$CERVEAU_HOME`, sinon `$XDG_DATA_HOME/cerveau`, sinon `~/.local/share/cerveau` |

```text
{config}/tenants/{tenant}/install.json
{data}/tenants/{tenant}/agents/{agent}/key.json
{data}/tenants/{tenant}/agents/{agent}/retired/{key_id}.json
{data}/tenants/{tenant}/agents/{agent}/queue.q
{data}/tenants/{tenant}/agents/{agent}/miss.log
```

Répertoires `0700`, fichiers `0600`. Une clé ou une file lisible par le groupe ou les autres est refusée. `tenant_id` et `principal_id` sont des jetons `[A-Za-z0-9_-]`, 64 octets au plus. L'identifiant d'agent fait au plus 64 octets, charset `[A-Za-z0-9._:-]`, sans `..`, sans `:` en bord, sans `-` en tête.

## Rotation et révocation

```bash
cerveau rotate --tenant acme --agent agent-box
cerveau revoke --tenant acme --agent agent-box --key-id gb-acme-agent-box-202610-1
```

`rotate` crée une clé active (`generation` + 1, nouveau `key_id`) et marque l'ancienne `retired`. La file est rechiffrée avec la nouvelle clé. Le compteur `seq` **ne repart pas à 1** : il appartient au couple tenant + agent, pas au `key_id`. Les tours encore en file sont rescellés avec la clé active au moment de l'envoi. Après la migration, la graine retirée est effacée du disque ; la clé publique et le statut restent pour le bundle (`retired_key_ids`).

`revoke` passe une clé déjà retirée à `revoked`. On ne révoque pas la clé active sur place : on la fait tourner, puis on révoque l'ancienne si le backend doit la refuser. Le bundle d'enregistrement liste les deux séries pour que l'opérateur les retire.

## Contrat `gb.run.v1` version 2

Schémas : `gb.run.v1` version **2** sur le fil, `gb.run.body.v2` dans le clair, `gb.turn.v1` pour l'enveloppe, `gb.canon.v1` pour le JSON canonique, `gb.queue.v2` pour la file, `gb.install.v1` pour l'installation, `gb.agent_key.v1` / `gb.agent_pub.v1` pour les clés, `gb.register.v1` pour le bundle.

La version 1 signait `schema|run_id|seq|sent_at|key_id|ciphertext` et laissait `replay` hors signature. La version 2 ajoute `tenant_id`, `principal_id`, `replay` et `actor` à la préimage **et** aux données associées. Changer `replay` exige un nouveau sceau.

Le JSON canonique trie les clés d'objet par unités de code UTF-16. Les chaînes suivent l'échappement `serde_json`. Les entiers n'ont pas de partie fractionnaire. Pas d'espace.

### Identifiants

`run_id` et `key_id` : ASCII `[A-Za-z0-9_-]`, non vides. `run_id` ≤ 80 octets, `key_id` ≤ 160. `key_id` : `gb-{tenant}-{agent}-{YYYYMM}-{generation}`. L'acteur est `gb:{tenant}:{agent}`. `sent_at` est `YYYY-MM-DDTHH:MM:SSZ`. Les `run_id` produits ici valent `run_` + ULID.

### Attribution

Seul un texte que le principal configuré a tapé dans ce tour porte son identifiant.

| Origine | `role` | `from` | `untrusted_user_input` |
| --- | --- | --- | --- |
| Principal (`human`, ou `role: "user"` avec `human_typed: true`) | `user` | `principal_id` configuré | `false` |
| Agent relaié | `agent` | son identifiant réel | `true` |
| Mention externe, entrée inbound | `inbound` | l'expéditeur réel | `true` |
| Outil | `tool` | le nom réel de l'outil | `false` |

Un `from` sur un message humain doit être absent ou égal au `principal_id`. Un nom d'affichage n'est pas accepté. Un rôle `user` sans `human_typed: true` est refusé. Reprendre le `principal_id` comme `from` d'un agent relaié, d'un inbound ou d'un outil est refusé. Le transcript brut n'a pas d'expéditeur.

JSON : `{"origin":"human","text":"…"}` ou `{"origin":"relayed_agent"|"inbound"|"tool","from":"…","text":"…"}`. Le rôle `user` exige `human_typed: true`.

Bornes après filtre, sur les champs structurés : déclencheur 500 caractères, 16 derniers messages × 1200, 8 derniers outils × résumé 400, 20 dernières décisions × fait 400. Le transcript verbatim est filtré mais pas tronqué. `from`, `role` et les identifiants ne sont pas filtrés.

### Filtre de secrets

Le filtre tourne **avant** le chiffrement et ne masque que le segment reconnu. Un hexadécimal de 40 caractères devient `[REDACTED:hex]` ; le reste de la phrase reste.

Détecteurs, du plus prioritaire au moins prioritaire : clé privée PEM, mot de passe d'URL (le mot de passe seul), JWT `eyJ…`, jetons `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_`, jeton Slack `xox…`, clé d'accès `AKIA`, clé `xai-`, clé `sk-`, `Bearer`, affectation `password` / `secret` / `api_key` / `token` (la valeur seule), hex `[0-9A-Fa-f]{40,}`, base64 `[A-Za-z0-9+/]{64,}={0,2}`. Courriels et téléphones sont désactivés sauf demande.

### Sceau

Ce n'est pas HPKE (RFC 9180). Algorithme : `x25519-hkdf-sha256-chacha20poly1305`.

La clé X25519 de l'agent est le scalaire libsodium / RFC 8032 : `SHA-512(graine ed25519)`, 32 premiers octets, puis clamp.

- `eph_shared = X25519(eph_sk, clé_publique_destinataire)`
- `static_shared = X25519(scalaire_agent, clé_publique_destinataire)`
- Les deux secrets doivent être contributifs.
- IKM = `eph_shared || static_shared` (64 octets).
- Sel = `epk || clé_X25519_publique_agent || clé_X25519_publique_destinataire` (96 octets).
- Info = `gb.run.v1/x25519-hkdf-sha256-chacha20poly1305` || `0x00` || `recipient_key_id` || `0x00` || `key_id`.
- Nonce : 12 octets aléatoires, publiés, non mélangés au HKDF.

Données associées, UTF-8, saut de ligne final :

```text
gb.run.v1
version=2
tenant_id={tenant_id}
principal_id={principal_id}
run_id={run_id}
seq={seq}
sent_at={sent_at}
replay={true|false}
actor={actor}
key_id={key_id}
recipient_key_id={recipient_key_id}
```

Préimage de signature :

```text
gb.run.v1|{version}|{tenant_id}|{principal_id}|{run_id}|{seq}|{sent_at}|{replay}|{actor}|{key_id}|{ciphertext_base64}
```

`sig.signed` est le SHA-256 de cette préimage, hexadécimal minuscule. `sig.value` est la signature ed25519 des 32 octets bruts, en base64. `replay` vaut `true` ou `false`.

Le vecteur public est `tests/fixtures/gb_run_v1.json` (`tenant-test`, principal `p_owner`, `key_id` `gb-tenant-test-agent-test-202610-1`). Les graines sont `SHA-256("cerveau-public-test-vector-v1\0" || étiquette)` pour `agent`, `recipient`, `ephemeral` et `nonce`. Ce sont des fixtures, pas des secrets.

### File et ordre

Fichier `{data}/tenants/{tenant}/agents/{agent}/queue.q`. Écriture : temporaire `0600`, `fsync`, `rename`, `fsync` du fichier et du répertoire. Verrou `flock` sur `lock`.

Format : `GBQ2` || nonce 12 octets || ChaCha20-Poly1305. Clé : HKDF-SHA256, sel `gb.queue.v2`, IKM = graine ed25519, info = `gb.queue.v2` || `0x00` || `tenant_id` || `0x00` || `agent_id` || `0x00` || `key_id`. Le JSON interne (`gb.queue.v2`) garde le corps en clair **dans** ce fichier chiffré, avec `run_id`, `seq`, `sent_at` et `principal_id`, pour pouvoir resceller quand `replay` change. Le tour est enregistré et `fsync` avant tout envoi.

1. Rejouer toute la file, par `seq` croissant, avant tout envoi direct.
2. Ne jamais envoyer le tour N+1 avec `replay: false` tant que N est en file.
3. Seul le tour créé par cet appel, s'il est le plus ancien, part avec `replay: false`.
4. Tout tour plus ancien part avec `replay: true`, rescellé. Son enveloppe est ignorée.
5. Chaque RPC a son propre délai de 2 secondes.
6. Si un rejeu plus ancien échoue, le nouveau tour reste en file et le journal porte `queued_behind`.
7. Un doublon (`409`, `duplicate` / `already`) retire le tour sans utiliser l'enveloppe.
8. HTTP 200 sans enveloppe retire le tour. Une erreur de transport le laisse en file.

Un redémarrage rejoue les tours persistés. Le bit `replay` n'est `false` que pour le tour vivant de l'appel en cours, en tête de file.

### Appel et enveloppe

Un JSON-RPC `tools/call`, outil `cerveau.run` par défaut (`CERVEAU_TOOL`). Corps limité à 2 Mio. Réponse JSON ou SSE. L'enveloppe est dans `result` si `schema` vaut `gb.turn.v1`, sinon `structuredContent`, `envelope`, ou `content[].text`.

Délai : 2 secondes par appel. Sans URL, le tour est mis en file et il n'y a pas d'enveloppe. Journal `{répertoire_agent}/miss.log` : `ts= agent= run_id= seq= reason=`.

`gb.turn.v1` n'est accepté que si : `schema`, `version` `1`, `builder` `eg:cerveau` (nom de protocole de l'enveloppe, pas une adresse), `envelope_id`, `run_id` de la grammaire, `generated_at`, `expires_at`, `ttl_seconds` exactement `300`, `expires_at = generated_at + 300s`, `agent.actor` égal à l'acteur de la clé, `integrity.alg = ed25519`, `integrity.key_id` égal à la clé de signature épinglée. Condensat : SHA-256 du corps canonique sans `integrity`. Décalage futur toléré : 60 secondes. Seule une enveloppe fraîche devient un `TurnContext`.
