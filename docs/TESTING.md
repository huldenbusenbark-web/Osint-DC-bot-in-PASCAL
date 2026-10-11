# Verification record

Verified during creation on **2026-10-10, America/Los_Angeles**.

| Environment | Version |
|---|---|
| OS | Debian GNU/Linux 13, x86-64 |
| Free Pascal | 3.2.2, Debian package `3.2.2+dfsg-46` |
| libcurl | `8.14.1-2+deb13u5` |
| libsodium | `1.0.18-1+deb13u1` |

## Results

| Check | Result |
|---|---|
| `make all` | Native bot compiled and linked |
| `sentinel --commands` | Valid JSON; 8 roots and 25 leaf commands |
| `make test` | **107 passed, 0 failed** |
| `make integration` | **24 HTTP integration tests passed** |
| `make smoke` | **3 public API checks passed** |

### Native tests

`tests/test_suite.lpr` is compiled with range, overflow and I/O checking. It covers:

- Canonical public IP, domain, date and UTF-8 clipping behavior.
- Blocking of loopback/private/link-local/CGNAT/multicast/documentation addresses, mapped IPv6, ambiguous IPv4, NUL suffixes and non-domain inputs.
- Output length, code-fence escaping and disabled mention parsing.
- Valid and modified Ed25519 signatures, stale/future timestamps and wrong keys.
- Guild boundaries, investigator/pentest role combinations, scoped target lookup and expiry.
- HTTPS request pinning and the body-free root HEAD request shape, without connecting to that target.
- Command schema, option validation and absence of shell/active-Shodan commands.
- Documented API routes, authentication placement and URL encoding.
- Optional-key behavior and Shodan search-credit opt-in.
- Cache reuse across locally limited views, provider cooldowns and HTTP 429 gating.
- Known-field-only rendering that excludes embedded leak/infostealer examples.
- Four-job capacity, five-command user allowance, replay suppression, cancellation and target cooldown.

Tests use clearly synthetic IDs and keys. `example.com`/a public IPv4 in a scope fixture are used only for constructing and validating requests; no TCP or HTTP check is sent to that fixture target.

### HTTP integration tests

`tests/integration.py` is a Python-standard-library test driver. It generates a **test-only** Ed25519 key through libsodium and launches the **Pascal** `bin/test_server` on a temporary local port.

That executable uses `TRecordingTransport` in place of `TCurlTransport`: all outbound requests are recorded locally and satisfied with fixtures. It cannot access Discord or provider endpoints through its transport.

Coverage includes signed Unicode PING, unsigned/malformed/stale/future signatures, exact raw-body verification, wrong application/guild, missing roles, no admin bypass, DM rejection, private immediate/deferred replies, background result editing, duplicate delivery suppression, mock FFraud flow, user limits, unknown targets, body rejection before upload, unsupported chunked transfer, route/method checks and token-free audit output.

The harness terminates its child process and removes its temporary files. The test server is **not** a deployable alternative to `bin/sentinel`.

### Optional live checks

`tests/live_smoke.lpr` makes only these three public requests through the actual Pascal/libcurl binding:

1. FFraud public IP lookup of `1.1.1.1`, with certificate metadata collected from the same ordinary HTTPS connection.
2. Ransomware.live v2 recent victims, rendering one record locally.
3. RansomLook one most recent post.

All three returned HTTP-successful, parseable responses matching the current renderer. Full incident records are not retained as fixture files, and victim names are not printed in the smoke-test summary.

This smoke test makes network requests and can fail due to provider downtime, quotas or later schema changes. Do not run it in a tight loop; respect the providers' terms and rate limits.

## Not verified with real credentials/deployment

- A real Discord application/guild invitation, bulk registration and final webhook edit.
- Shodan's authenticated endpoints or query-credit accounting.
- FFraud's authenticated routes and email reputation endpoint against a live account.
- Ransomware.live Pro with a real key.
- Docker daemon build/run, public TLS/reverse-proxy configuration or systemd installation.
- Active checks against any real target.

These limitations are intentional and must not be described as completed live verification. API request contracts and local security behavior are tested separately from account provisioning and hosted deployment.

## Reproduce

```bash
make clean
make all test
make integration  # requires Python 3; no Python package installs
make smoke        # optional public network access
```

Check command JSON independently:

```bash
./bin/sentinel --commands > commands.json
python3 -m json.tool commands.json >/dev/null
```

For an authorized deployment test, first configure your own application, a test guild and a target you control. Start with `/help`, `/status`, `/pentest scope` and a passive lookup. Do not enable an active target just to make a test pass.
