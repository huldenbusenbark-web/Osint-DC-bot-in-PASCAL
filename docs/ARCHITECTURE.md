# Architecture

## Request path

```text
Discord signed HTTP interaction
    -> HTTPS reverse proxy (body/header/time limits)
    -> Free Pascal TFPHTTPServer on 0.0.0.0:8080
       -> raw-body Ed25519 + timestamp verification
       -> application ID / command shape / guild / role checks
       -> replay, per-user and worker admission gates
       -> HTTP 200: type 5, flags 64 (deferred, private)
          -> background TThread
             -> fixed provider adapter + memory cache + cooldown
                OR exact, unexpired authorized target
             -> allowlisted result fields -> bounded plain-text report
             -> PATCH Discord's original interaction response
             -> metadata-only audit event; release worker slot
```

The Discord bot token is used only by the explicit `--register` command. Worker replies use the short-lived token in the signed interaction. There is no gateway connection, message-content intent or bot-token requirement in the serving path.

## Modules

| File | Responsibility |
|---|---|
| `sentinel.lpr` | CLI modes, initialization, lifetime |
| `sp_common.pas` | IP/domain/date validation, JSON field access, display safety |
| `sp_config.pas` | Environment file, ACLs, exact target scopes, expiry checks |
| `sp_crypto.pas` | Native libsodium Ed25519 verification |
| `sp_http.pas` | Native libcurl transport, TLS checks, deadlines, response caps, IP pinning |
| `sp_commands.pas` | The 25-command schema and strict option parsing |
| `sp_providers.pas` | Fixed API contracts, key handling, cache, provider cooldowns |
| `sp_reports.pas` | Known-field-only summaries; no generic JSON dumps |
| `sp_pentest.pas` | Bounded TCP connects, HTTPS HEAD/certificate observations, DoH |
| `sp_engine.pas` | Command dispatch and partial cross-provider summaries |
| `sp_state.pas` | Admission, replay memory, user/target gates, JSON audit events |
| `sp_discord.pas` | Registration, original-response edits, bounded HTTP-status retries |
| `sp_server.pas` | HTTP endpoint, request caps, signature/auth boundaries, job lifecycle |

## Concurrency and ownership

- Each HTTP connection is handled by FPC's connection thread. The connection count is limited to 32; a reverse proxy remains mandatory.
- Commands use separate worker threads, with a hard admission limit of four. There is no unbounded command queue.
- `TBotConfig` is immutable after startup. Reload requires a restart. Never mutate it from a command handler.
- `TTransport.Send` creates a separate curl easy handle for each request. Global curl/sodium initialization happens before threads start.
- `TProviderHub` holds its lock only around cache/cooldown state, not during network I/O. Provider gates prevent near-simultaneous cache-miss stampedes.
- Cached values are immutable strings. Each caller parses its own JSON document and must free `TApiReply.JSON` in a `finally` block.
- `TBotState` serializes admission, counters and audit writes. Worker threads always release their slot.
- Short-lived interaction tokens are not stored to disk. A worker starts only after its deferred acknowledgement has been sent.

## Limits

These are deliberate constants rather than a remote administrative control surface.

| Limit | Current value |
|---|---|
| Accepted signature age | Up to 300 seconds old, up to 30 seconds future skew |
| Replay memory | 10 minutes; at most 4,096 accepted IDs |
| Incoming body | 64 KiB, enforced before reading oversized declared bodies |
| Incoming connections | 32; socket I/O timeout 5 seconds |
| Provider JSON | 4 MiB; nesting depth at most 48 |
| Response headers | 64 KiB |
| Provider HTTPS timeouts | 4-second connect, 12-second total per request |
| User commands | 5 per user per 60-second fixed window, across configured guilds |
| Concurrent jobs | 4 |
| Target checks | 1 per guild/alias per 60 seconds |
| General provider gate | 1 second per provider; per-record-type for DoH |
| Ransomware.live v2 gate | 60 seconds per operation, across all arguments |
| Cache | 5-minute TTL; 64 entries; 8 MiB total raw bodies; skip items over 2 MiB |
| TCP check | 1 target, up to 8 explicit ports, 800 ms per connect |
| Output | At most 1,800 UTF-8 bytes of report text before fencing; no attachments |
| Discord retries | At most 3 attempts for HTTP 429/5xx; individual retry delay at most 5 seconds |

A provider error does not trigger an automatic API retry. HTTP 429 sets a cooldown; integer `Retry-After` values are used with a 1–3,600-second bound, otherwise 60 seconds. Cached data is returned before provider cooldown checks. Cache hits retain the original fetch timestamp; they are not relabeled as fresh observations.

## Extending safely

1. Add a command specification and validate its option shape in `sp_commands`.
2. Add a **fixed-origin, fixed-method** plan in `sp_providers`. Never accept a user-supplied base URL or raw HTTP headers.
3. Give it a cache key without credentials and a conservative rate bucket.
4. Add a renderer that selects known fields, rather than exposing the entire JSON document.
5. Add fixture tests, invalid-input tests and a mock transport assertion for the exact route/authentication method.
6. If it touches a target directly, require the existing pentest role and scope path. Do not reuse passive search results as an active allowlist.

The engine assumes its caller has authenticated/authorized the interaction; `sp_server` is that security boundary. A future CLI or scheduled-job front end must supply equivalent authorization, not call `Run` on arbitrary user input.
