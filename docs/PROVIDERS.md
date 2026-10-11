# Provider contracts and provenance

Documentation was inspected for this build on **2026-10-10 (America/Los_Angeles)**. The endpoint constants are intentionally explicit; the application does not guess endpoints or fall back to scraping.

## FFraud

Base: `https://api.ffraud.com`

| Bot command | No key | With `FFRAUD_API_KEY` |
|---|---|---|
| `ffraud ip` | `GET /public/ip/{ip}` | `POST /v1/ip/check`, JSON `{"ip":"..."}` |
| `ffraud email` | `POST /public/email/check` | `POST /v1/email/check` |

Email body: `{"email":"..."}`. Authenticated requests send `X-API-Key: ...`, never a key in a Discord command. IP and email response fields are selected explicitly; arbitrary nested `whois`/company data is not dumped.

References: [IP contract](https://ffraud.com/docs/ip-intelligence), [email contract](https://ffraud.com/docs/email), [authentication](https://ffraud.com/docs/authentication), [machine-readable schema](https://ffraud.com/openapi.json). Public single-IP lookups are documented on the provider's home page. [1](https://ffraud.com/)

The email command discloses the submitted address to FFraud. It is a reputation check, not a person-search or identity-verification feature. Only use addresses you may submit to that service.

## Ransomware.live

| Operation | v2: `https://api.ransomware.live/v2` | Pro: `https://api-pro.ransomware.live` |
|---|---|---|
| Recent | `/recentvictims` | `/victims/recent` |
| Search | `/searchvictims/{keyword}` | `/victims/search?q={keyword}` |
| Groups | `/groups` | `/groups` |
| Group | `/group/{name}` | `/groups/{name}` |

All are GET. Pro sends `X-API-KEY`; v2 sends no credentials. Display limits are applied locally where the provider returns a whole document. The renderer accepts a root array or the documented/common `victims` wrapper, and distinguishes current `victim`/`group` from older `post_title`/`group_name` fields.

The public v2 service is personal-use-only and rate limited to one request/minute per endpoint. This implementation uses a conservative operation-wide gate, so two different v2 group lookups within a minute are also gated. It does not silently fall back from Pro to v2 on authentication errors. [1](https://www.ransomware.live/api)

References: [2](https://www.ransomware.live/apidocs), [Pro documentation](https://api-pro.ransomware.live/docs), [Pro Swagger schema](https://api-pro.ransomware.live/swagger.json).

Displayed victim fields are organization name, group, country and observed date. Raw claim URLs, screenshots, infostealer subobjects and contact details are omitted. A provider's listing is not independent confirmation of a breach; discovery time is not necessarily attack time.

## RansomLook

Base: `https://www.ransomlook.io/api`

| Operation | GET path |
|---|---|
| Recent | `/recent/{number}` |
| Search | `/search?q={keyword}` |
| Groups | `/groups` |
| Group | `/group/{name}` |
| Statistics | `/stats` |

The published Swagger definitions take precedence where prose examples differ:

- `/search` declares **`q`**, not the `query` parameter shown in a Python example.
- `/recent/{number}` is a **post count**; `/last/{number}` is a **day count** and is not used here.
- Search returns a cross-entity object. This bot renders its `posts` array, not `leaks`, `notes` or market records.
- Group detail is `[group_object, posts_array]`; the renderer uses the first object only.

Reference: [1](https://www.ransomlook.io/doc/) and the [published Swagger JSON](https://www.ransomlook.io/swagger.json). No export, torrent, file-server, leak-download or private API commands are registered.

## Shodan

Base: `https://api.shodan.io`

| Operation | GET path |
|---|---|
| Host | `/shodan/host/{ip}?minify=true` |
| Search | `/shodan/host/search?query=...&page=1&minify=true` |
| Count | `/shodan/host/count?query=...&facets=country:3` |
| DNS | `/dns/resolve?hostnames=...` |
| Account | `/api-info` |

Shodan's documented `key` query parameter is appended by the adapter. This is why request URLs and native exception messages must never be logged. Search is disabled until `SHODAN_SEARCH_ENABLED=true`; it can use query credits. Count does not consume query credits under the documented API contract. [1](https://developer.shodan.io/api)

Host and search commands are passive index lookups. This application never calls `/shodan/scan`, an exploit API, or a host returned by Shodan. It displays indexed CVE IDs as **unverified here**, not as confirmed exploitable vulnerabilities.

## Supplemental DNS

The scoped DNS command uses fixed-origin GET requests to:

`https://cloudflare-dns.com/dns-query?name=...&type=A|AAAA|CAA`

It sends `Accept: application/dns-json`. This is a third-party DNS observation, not a port scan or an authoritative DNSSEC audit. Returned addresses never modify active-check scope.

## Failure semantics

- Missing key: clear disabled/configuration response, without a request.
- HTTP 401/403: generic authentication/plan error; response body not exposed.
- HTTP 404: provider has no record at that endpoint; not a "clean" verdict.
- HTTP 429: cooldown; no tight automatic retry loop.
- Redirect, malformed/oversized JSON, or unexpected schema: explicit failure rather than invented data.
- Cross-provider intelligence commands keep partial successes and identify the failed source.

See `tests/live_smoke.lpr` for the three keyless live checks and `docs/TESTING.md` for the unauthenticated-versus-mocked coverage boundary.
