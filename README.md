# Sentinel — a native Pascal OSINT Discord bot

**25 slash commands. Four intelligence providers. Explicitly scoped, non-destructive checks.**

The bot, HTTP interaction server, provider adapters, command registration, authorization, caching and TCP checks are written in **Free Pascal**. It calls native **libcurl** for verified HTTPS and **libsodium** for Discord's Ed25519 signatures. There is no Python, Node.js, Discord SDK or shell-command wrapper in the bot runtime. Python is used only by the optional black-box test harness.

**Target platform:** Linux x86-64; built and tested with Free Pascal 3.2.2 on Debian 13. This is not a Delphi/Windows or Turbo Pascal project.

## What's included

- FFraud IP reputation and email checks; public endpoints or an optional key.
- Ransomware.live **v2 and Pro** adapters, selected explicitly in configuration.
- RansomLook recent posts, organization search, group metadata and statistics.
- Shodan host lookups, search, counts, DNS and account-credit information.
- Cross-provider `/intel ip` and `/intel org` summaries with source attribution.
- Allowlisted TCP connect checks, HTTPS header observations, verified TLS certificate metadata and DNS observations.
- Signed requests, timestamp validation, replay suppression, guild/role allowlists, private replies and immediate deferred acknowledgements.
- Four worker slots, per-user/per-target/provider cooldowns, bounded memory caching, limited responses and metadata-only audit logs.
- Native tests, signed HTTP integration tests, an optional live smoke test, Docker/systemd recipes and an HTTPS reverse-proxy example.

This is a working, tested starting implementation—not a hosted bot or an independently audited production service. Bring your Discord application, provider credentials where needed, domain and HTTPS hosting.

## 1. Build

On Debian 13:

```bash
sudo apt-get update
sudo apt-get install -y make fp-compiler fp-units-fcl fp-units-net \
  libcurl4-openssl-dev libsodium-dev ca-certificates
make
make test
```

The executable is `bin/sentinel`. All bot source is under `src/`.

## 2. Configure

```bash
cp .env.example .env
cp config.example.json config.json
chmod 600 .env config.json
```

Edit both files. Replace the application/guild/role placeholders with your actual IDs. No credentials are bundled.

| Setting | Purpose |
|---|---|
| `DISCORD_APPLICATION_ID` | Your Discord application's ID |
| `DISCORD_PUBLIC_KEY` | Its 64-character hexadecimal public key—not the bot token |
| `DISCORD_BOT_TOKEN` | Needed only to register commands; can be removed from the running service |
| `FFRAUD_API_KEY` | Optional; blank selects the public endpoints |
| `SHODAN_API_KEY` | Required for Shodan commands |
| `SHODAN_SEARCH_ENABLED` | Default `false`; set `true` to allow searches that may spend query credits |
| `RANSOMWARE_LIVE_MODE` | `v2` or `pro`; default `v2` |
| `RANSOMWARE_LIVE_API_KEY` | Required only in Pro mode |
| `PORT` | Local HTTP port; default `8080` |

The public RansomLook endpoints used here do not require export credentials. FFraud documents separate public and authenticated routes. [1](https://ffraud.com/)

**Ransomware.live v2 is designated for personal use and is limited to one request/minute per endpoint.** For organizational use, review the provider's terms and choose the appropriate Pro access; don't treat v2 as an unrestricted business feed. [1](https://www.ransomware.live/api)

The `.env` reader supports `NAME=value`, full-line comments and optional matching quotes. It does **not** execute shell code, expand variables, support multiline values or strip inline comments. Existing process environment variables take precedence, even if empty.

Validate locally without contacting any API:

```bash
./bin/sentinel --check
```

## 3. Connect Discord

1. Create a Discord application and copy its **Application ID** and **Public Key** into `.env`. Create a bot token for command registration. Keep tokens out of Discord messages and source control.
2. Install the application in your guild with `applications.commands` and, if using a bot installation, `bot`. It does **not** need the Administrator permission or privileged gateway intents.
3. Configure the exact guild ID and investigator role IDs in `config.json`. Set `pentest_roles` to an empty array if no one should be able to run that command group.
4. Run `./bin/sentinel --serve` behind a trusted HTTPS reverse proxy. The application binds `0.0.0.0:8080`; **firewall direct access to that port**. Use `deploy/nginx.conf.example` as a starting point.
5. Set the application's **Interactions Endpoint URL** to `https://YOUR_DOMAIN/interactions`. Discord's signed verification PING should succeed. Raw request bodies and signature headers must pass through the proxy unchanged.
6. Register guild commands:

   ```bash
   ./bin/sentinel --register
   ```

   **Important:** this uses Discord's bulk overwrite operation. It replaces this application's command set in each configured guild. It does not modify other applications or register global commands.

7. Commands have `default_member_permissions: "0"` by default. In the guild's application/integration command permissions, explicitly grant your investigator role access. Give the pentest role the relevant command access too. Members still need the runtime roles configured in `config.json`; even Discord administrators do not bypass that check.
8. Try `/help` and `/status`. After registration, remove `DISCORD_BOT_TOKEN` from the running service if you don't need it there.

The bot uses **HTTP interactions**, not a Gateway WebSocket. It does not maintain an online presence indicator or listen to ordinary channel messages. That is intentional. Discord requires an initial response within three seconds; this implementation acknowledges first and edits the private response from a worker. [1](https://docs.discord.com/developers/interactions/receiving-and-responding)

## Commands

Arguments use Discord's slash-command options. List/search commands marked below accept `limit:1..10`, default `5`.

| Command | Behavior |
|---|---|
| `/help` | Command guide and data-handling notes |
| `/status` | Configuration/capability status, not an API health probe |
| `/ffraud ip address:IP` | Fraud score, network, proxy/VPN/Tor and abuse signals |
| `/ffraud email address:EMAIL` | Format, disposable, role-address and reputation signals |
| `/rlive recent [limit]` | Recent organization victim claims |
| `/rlive search query:ORG [limit]` | Search organization names/domains |
| `/rlive groups [limit]` | First tracked groups returned by the API |
| `/rlive group name:GROUP` | Group background/activity metadata |
| `/rlook recent [limit]` | Latest posts, using the count-based endpoint |
| `/rlook search query:ORG [limit]` | Post metadata from cross-entity search |
| `/rlook groups [limit]` | First tracked group names |
| `/rlook group name:GROUP` | Group metadata, excluding leak-site locations |
| `/rlook stats` | Provider aggregate statistics |
| `/shodan host address:IP` | Indexed ports, hostnames and vulnerability IDs |
| `/shodan search query:QUERY [limit]` | First-page passive search; explicit credit-usage opt-in |
| `/shodan count query:QUERY` | Total matches and a small country breakdown |
| `/shodan dns name:DOMAIN` | Provider DNS resolution |
| `/shodan account` | Plan and credit balances; never keys |
| `/intel ip address:IP` | FFraud + Shodan, with partial results if a source fails |
| `/intel org query:ORG` | Up to two claims from each ransomware tracker |
| `/pentest scope` | This guild's configured targets |
| `/pentest ports target:ALIAS` | One TCP connect per approved port, at most eight |
| `/pentest headers target:ALIAS` | One pinned `HEAD /` over HTTPS; header presence only |
| `/pentest tls target:ALIAS` | Verified TLS chain/hostname + leaf-certificate metadata |
| `/pentest dns target:ALIAS` | A, AAAA and CAA observations via Cloudflare DoH |

Shodan commands query its existing index; the application has **no active Shodan scan endpoint**. The count method does not consume query credits according to Shodan's documentation; search privileges/credit usage depend on the account. [1](https://developer.shodan.io/api)

All responses are **ephemeral** and mention parsing is disabled. Long results are truncated, not silently exported or posted publicly. No pagination, file export or scheduled-alert subsystem is implemented.

## Authorize a pentest target

Targets are disabled initially: `"targets": []`.

Only add assets you have written permission to test. Add an entry to that array, replacing **every placeholder**:

```json
{
  "alias": "edge",
  "guild_id": "YOUR_GUILD_ID",
  "hostname": "app.example.com",
  "ipv4": "YOUR_AUTHORIZED_PUBLIC_IPV4",
  "ports": [80, 443],
  "expires": "YYYY-MM-DD"
}
```

- `hostname` must be your exact ASCII/punycode domain, with no scheme, path or wildcard.
- `ipv4` must be a canonical **public IPv4 you are authorized to test**. Private, loopback, link-local, multicast, documentation and several special-use ranges are rejected. This version does not support active IPv6 or private-network labs.
- `ports` contains 1–8 explicit TCP ports. HTTPS checks require `443` in this list.
- `expires` is an inclusive UTC date. Expired scopes fail closed at startup and are checked again when used. Restart after editing configuration.
- A member needs **both** an investigator role and a pentest role. There is one check per target per minute, shared by its pentest subcommands.

HTTPS requests are pinned to the configured IP while keeping the hostname for SNI/certificate verification. Redirects and proxies are disabled. DNS observations **never** add targets or change the pin. There are no brute-force, exploit, shell, credential, stress-test, arbitrary-URL or leak-download commands.

## Run as a service

- **Container:** `docker compose build`, then `docker compose up -d`. The supplied recipe publishes only to host loopback, runs as an unprivileged user, uses a read-only filesystem and applies resource limits. Ensure the mounted `config.json` is readable by container UID 10001. Run registration with `docker compose run --rm --no-deps sentinel --register /app/config.json` when needed.
- **systemd:** adapt `deploy/sentinel.service`, create its service user and install the binary/config/environment file at the paths shown. The `.env` file is optional when systemd supplies the environment. Firewall port 8080 to the local reverse proxy.
- Health endpoint: `GET /healthz`. It reports process HTTP liveness, not provider availability.

Use **one running instance**. Cache, replay suppression and limits are process-local. SIGTERM drains current work; jobs are not durable across crashes. Keep the host clock synchronized. The deployment recipes are provided but were not launched against a real Discord application here.

## Verification

```bash
make test                     # native tests, no network
sudo apt-get install python3 # only needed for the next optional harness
make integration              # signed local HTTP tests; all outbound APIs mocked
make smoke                    # OPTIONAL: makes three public API requests
```

Recorded verification: **107 native checks passed, 24 black-box HTTP tests passed, three public API smoke checks passed.** The public checks covered FFraud, Ransomware.live v2 and RansomLook; the FFraud request also exercised libcurl's certificate metadata binding.

No live Discord credentials, authenticated FFraud key, Shodan key or Ransomware.live Pro key were supplied. Those authenticated paths are implemented from the documented contracts and tested with mocks, **not certified by a live account test**. No active pentest command was run against a third-party target.

See [TESTING](docs/TESTING.md), [SECURITY](docs/SECURITY.md), [provider contracts](docs/PROVIDERS.md) and [architecture](docs/ARCHITECTURE.md) for limitations and maintenance notes.

**Interpretation matters:** ransomware listings are third-party claims; reputation scores and Shodan vulnerability IDs are leads, not proof. An empty result is not evidence that an organization is safe. Only submit email addresses or other query data you are permitted to disclose to the relevant provider.

Code license: MIT. Provider data and services have separate terms.
