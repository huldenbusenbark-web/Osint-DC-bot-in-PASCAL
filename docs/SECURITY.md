# Security model and operational limits

## Intended boundary

This bot supports defensive infrastructure intelligence and tests of **explicitly authorized assets**. Passive intelligence and direct target checks are separate paths. Search results, DNS answers and provider-supplied links never become authorized targets.

The shipped configuration permits **no targets**. A configured scope is an operator's authorization record, not an automated proof that they own an asset. Confirm ownership, written permission, time window and third-party/cloud-provider constraints yourself. Do not assume a shared CDN IP is yours to scan because your hostname resolves there.

## Implemented controls

- Ed25519 verification covers the exact HTTP timestamp header plus raw body. Verification happens before parsing or authorization.
- Timestamp checks reject old or far-future requests. Accepted interaction IDs are retained for 10 minutes to prevent duplicate jobs within one process.
- Only the configured application and allowlisted guilds/roles can execute commands. Direct messages are rejected. An administrator permission bit is not a bypass.
- All pentest subcommands require an additional configured role. Active checks re-read the immutable target definition and re-evaluate expiry for each job.
- No target ranges, wildcard hosts, arbitrary URLs, redirects, proxies, version probes, application payloads, passwords or operating-system commands are accepted.
- TLS requests preserve hostname verification and trust-chain verification. Certificate failure produces an error; there is no `--insecure` retry.
- HTTPS target requests use libcurl address pinning (`CURLOPT_RESOLVE`) and verify the connected IP. They are restricted to `HEAD /` on port 443. Response redirects are reported but not followed.
- TCP checks operate on one numeric configured IPv4, connect once per listed port and immediately close. A timeout is not labeled "closed".
- Targets reject loopback, private, link-local, multicast and documented special-use IPv4 ranges. Active IPv6 and private lab targets are intentionally unsupported in this version.
- Responses are private/ephemeral, mention parsing is empty, and untrusted text is fenced with internal backticks removed. Display text and record counts are bounded.
- Incoming declared body size, provider body size, JSON nesting, connection count, job count, API rates and cache storage are bounded. No unbounded queue or bulk export is present.

## Secrets and data handling

The serve path needs the Discord public key, not its bot token. Command registration is a separate operator action. Store API credentials in a secret manager/environment or a tightly permissioned `.env`; never in a slash command.

Audit output is newline-delimited JSON to stdout. Fields are timestamp, interaction ID, guild ID, actor ID, command name, outcome and elapsed time. **Arguments, email addresses, API keys, raw bodies, headers, interaction tokens and provider URLs are not intentionally logged.** Discord user/guild IDs in audit records are still operational identifiers: control access and retention in your logging system.

Provider responses are held in process memory. The cache can retain **raw API JSON**, including fields not displayed, for up to five minutes; it is not written to disk. Avoid processing data whose policy forbids this, and restrict debugger/core-dump access. This program is not a secure-erasure library: clearing a string does not guarantee that every historical heap copy of a secret is wiped.

Private Discord responses are not end-to-end encrypted and can be copied by the recipient. Queries are disclosed to the selected API provider. In particular, the email command submits the complete address to FFraud. The bot does not follow victim/leak-site links, download stolen datasets, or expose infostealer details in its reports.

Scores, blacklist flags and indexed CVEs can be incomplete or wrong. They are not identity attribution or evidence that a host is exploitable. Missing data is not a clean bill of health.

## Deployment requirements

1. Put the FPC server behind a maintained HTTPS reverse proxy with trusted certificates. The provided nginx example bounds headers/bodies, buffers incoming requests and applies source limits.
2. **Do not expose port 8080 directly to the Internet.** It intentionally binds all interfaces for container compatibility. FPC's built-in header reader is not a hardened public edge server; socket timeouts are not an absolute request deadline.
3. Run as an unprivileged account. Set process memory/task limits, restrict filesystem access and disable core dumps where appropriate. Review cloud metadata routes and egress policy too.
4. Keep Free Pascal's runtime, libcurl, libsodium, CA certificates and the OS patched. Require libcurl 7.85 or newer for `CURLOPT_PROTOCOLS_STR`; this build used 8.14.1.
5. Synchronize the host clock and restart after changing config or keys. Config does not hot-reload. Expired targets must be removed or renewed before startup.
6. Operate one instance. Replay state, rates and cache reset at restart and are not shared across replicas. A distributed deployment requires a shared admission/replay/quota store and idempotent delivery design.
7. Review proxy/log collector configuration separately. Don't enable request-body logging, credential-bearing outbound URL logging or libcurl verbose traces in production.

## Explicit limitations

- The code has automated tests but **has not received an independent security audit**.
- API integration keys, real guild registration and externally terminated HTTPS deployment were not available for end-to-end account testing here.
- Active check behavior was tested through validation and mock transport; no third-party asset was actively scanned.
- TLS checks are not cipher/protocol enumeration or comprehensive revocation checks. Header presence is not header-policy validation; `HEAD` may differ from `GET`.
- IP special-use classifications change. Review `IsPublicIPv4`/`IsPublicIP` when updating the service; do not use this helper as your only network perimeter.
- There is no durable queue, scheduled monitoring, export, retry-after-crash workflow, interaction-token vault or multi-instance coordination.
- A crash can leave a deferred response unfinished. A final Discord edit that exhausts its bounded status retry budget produces a `delivery_failed` audit entry.
- Provider retention policies, ToS, business-use rights and API plan limitations remain the operator's responsibility.

Report issues privately to the maintainer of your deployed copy; this generated starter project does not ship with a hosted security-reporting service.
