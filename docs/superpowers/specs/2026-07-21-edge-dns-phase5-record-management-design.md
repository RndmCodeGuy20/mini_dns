---
tags: [decision, feature, arch]
status: active
supersedes: ""
related: []
complexity: high
---

# Edge DNS — Phase 5: Record management (persistence + CRUD API + auth)

## What

Makes the DNS record table runtime-managed instead of a reflash-only compile-time
constant: records persist in NVS, a JSON CRUD API (`POST`/`PUT`/`DELETE
/api/records`) lets a separate client (a React app, `curl`, anything) add/edit/
remove them, and the mutating routes require HTTP Basic auth. `GET` routes
(dashboard, `/api/records`, `/api/blocklist`, `/metrics`) stay open.

This is Phase 5 of the "edge DNS" vision, bundled as one phase (not three) because
its pieces are load-bearing for each other — see Why.

## Why

- **The problem:** every prior phase (forwarding, ad-block, metrics, mDNS) made the
  appliance more capable at *serving* queries, but the record table itself — the
  thing an "edge DNS appliance" exists to manage — was still `constexpr`, editable
  only by reflashing. That's fine for a POC, wrong for anything meant to run
  unattended on a LAN.
- **One phase, not three:** persistence without a CRUD API is pointless (nothing to
  persist besides the boot-time seed); `POST`/`PUT`/`DELETE` without persistence
  would silently revert every edit on reboot; either without auth would leave a
  mutating, unauthenticated endpoint exposed to the whole LAN. None of the three
  ships alone without leaving an unfinished half-feature — see `ARCHITECTURE.md`'s
  Phase 5 rationale.
- **The first genuinely shared *mutable* cross-task state.** Every prior exception to
  "no shared mutable state between tasks" kept the shared thing either
  immutable-after-boot (`DnsBlocklist`'s domain set) or a single atomic word
  (`DnsMetrics`' counters, `DnsBlocklist::blocks_total_`). The record table is neither:
  the DNS task reads it on every query, the HTTP task rewrites it on every edit,
  and a read has to observe an internally-consistent multi-field entry (hostname +
  ip together), which a bag of atomics can't provide.
- **Plain `std::mutex`, not an RCU/atomic-snapshot design.** A `std::mutex` inside the
  new `DnsRecordStore` is locked briefly by the DNS task's per-query lookup and by
  the HTTP task's mutations. Considered and rejected: an atomic
  `shared_ptr<const Table>` snapshot (lock-free reads, HTTP swaps a new table in) —
  more machinery than a LAN-scale, single-DNS-reader device needs; the mutex's cost
  is negligible next to the `recvfrom`/`sendto` syscalls already on that path. This is
  a deliberate, documented departure from the codebase's prior "lock-free DNS path"
  framing.
- **Lookup returns a copy, never a pointer.** `DnsRecordStore::find()` returns
  `std::optional<std::array<uint8_t,4>>` by value; the lock is released before the
  function returns. Returning a pointer/reference into `records_` would let the HTTP
  task free or relocate that memory (a `std::vector` reallocation on insert/erase)
  while the DNS task still held it — a copy makes that impossible by construction
  rather than by discipline.
- **HTTP Basic auth, credentials in a gitignored compile-time header.** Mirrors
  `wifi_credentials.h` exactly (same file, same "must be recreated by hand on a
  fresh clone" pattern) rather than an NVS-stored/rotatable credential — YAGNi'd for
  this phase since there's no change-password endpoint to make NVS storage pay for
  itself yet.
- **Auth on mutating routes only, not `GET /metrics`/`GET /api/*`.** Prometheus scrapes
  `/metrics` unauthenticated by design (Phase 3); gating it would break that model for
  no security benefit (nothing sensitive is disclosed by the read-only routes beyond
  what a LAN device already exposes).
- **Firmware ships a JSON API only — no bundled frontend rewrite.** The user is
  building the record-management UI as a separate React project against this API,
  so this phase's job is a correct, CORS-capable, documented API surface, not a UI.
  The existing `GET /` server-rendered dashboard is left as-is, unmodified, as a
  built-in fallback.
- **CORS: reflect the request's `Origin`, not a wildcard.** Browsers reject
  `Access-Control-Allow-Origin: *` combined with credentialed requests (Basic auth on
  the mutating routes sends `Authorization`, and CORS credentials mode is required
  for that header to be sent cross-origin) — so a wildcard literally cannot work here.
  Reflecting the origin is effectively open (any origin gets a matching
  `Allow-Origin`), leaning entirely on `check_auth()` rather than origin filtering for
  protection. Accepted as reasonable for a dev-facing LAN appliance; a compile-time
  origin allow-list was considered and rejected as reflash-to-retarget friction
  between dev (`localhost:5173`) and prod frontend origins.

## How (key parts)

### New module: `dns_record_store.h`/`.cpp`
`DnsRecordStore` (singleton `DnsRecordStore &record_store()`, same shape as
`blocklist()`/`metrics()`) holds `std::vector<DnsRecordEntry> records_` behind a
`std::mutex`. `DnsRecordEntry` is `{std::string hostname; std::array<uint8_t,4> ip;}`
— unlike the compile-time `dns_record_t` (`dns_records.h`), hostname is owned
storage, since entries are created at runtime. NVS persistence mirrors
`DnsBlocklist` almost exactly: namespace `"records"`, key `"list"`, one
newline-separated `hostname=A.B.C.D` blob (not one key per record — NVS keys cap at
15 characters). `load_from_nvs()` seeds from `DNS_RECORDS_DEFAULTS`
(`dns_records.h`, renamed from `DNS_RECORDS` — same "seed once, then NVS is
authoritative" role `DNS_BLOCKLIST_DEFAULTS` plays) on first boot. `create()`/
`update()`/`remove()` each lock, mutate, and call `save_to_nvs()` while still
holding the lock, so a concurrent reader can never observe an in-memory table that
doesn't match what's on flash. Capped at `DNS_RECORD_STORE_MAX_RECORDS` (64).

### `dns_server.cpp`: reading from the store
`find_dns_record()`'s linear scan over `DNS_RECORDS` is replaced by
`record_store().find(*qname)`, returning `std::optional<std::array<uint8_t,4>>` — a
copy, consumed immediately by `build_a_record_response()`. `dns_server_start()`
calls `record_store().load_from_nvs()` right beside the existing
`blocklist().load_from_nvs()`, before the DNS task starts and before
`http_server_start()` — same race-free ordering guarantee Phase 2 established.

### `http_server.cpp`: CRUD, auth, CORS
- `GET /api/records` reads `record_store().snapshot()` (a locked copy) instead of
  `DNS_RECORDS`.
- `POST`/`PUT`/`DELETE /api/records` are separate `httpd_uri_t` registrations on the
  same URI (esp_http_server dispatches by method), each: `add_cors_headers()` →
  `check_auth()` (401 + `WWW-Authenticate` on failure) → `read_json_body()` (cap
  1KB) → `parse_record_request()` (validates `host`/`ip`, 400 on failure) → the
  store call, mapped to `201`/`200`/`404`/`409`/`507`.
- `OPTIONS /api/records` answers CORS preflight (204 + headers, no auth — browsers
  never send credentials on a preflight).
- `check_auth()`: reads `Authorization`, base64-decodes the `Basic` token via
  `mbedtls_base64_decode` (`mbedtls/base64.h`, already vendored by ESP-IDF), compares
  to `ADMIN_USER`/`ADMIN_PASS` (`admin_credentials.h`).
- `add_cors_headers()`: reflects `Origin` into `Access-Control-Allow-Origin` +
  `Access-Control-Allow-Credentials: true` + fixed `Allow-Methods`/`Allow-Headers`.
- `valid_hostname()` (RFC 1035 label syntax) and `parse_ipv4()` (strict four-octet
  parse) reject malformed input to 400 before it reaches the store.
- `httpd_config_t::max_uri_handlers` bumped from the default (8, now an exact fit —
  4 prior GETs + 4 new records methods) to 12, for headroom.

### Build / credentials
`main/admin_credentials.h` (gitignored, created by hand — see README.md) defines
`ADMIN_USER`/`ADMIN_PASS`. `CMakeLists.txt` adds `dns_record_store.cpp` and the
`mbedtls` component (for base64).

## Gotchas

- **`httpd_resp_set_hdr()` stores a pointer, not a copy — the value string must outlive `httpd_resp_send()`.** Caught during hardware verification: `add_cors_headers()` originally declared its `Origin`-reading buffer as a local inside itself, called from each handler before `httpd_resp_send()`. The buffer went out of scope the moment `add_cors_headers()` returned, so by the time the handler actually sent the response, `Access-Control-Allow-Origin` serialized from a dangling pointer (observed on real hardware as an empty header value, not a crash). Fixed by moving the buffer into each handler's own stack frame and passing it into `add_cors_headers()` as an out-parameter, so it stays alive for the handler's whole lifetime. `esp_http_server.h`'s doc comment says this outright ("Make sure that the lifetime of the field value strings are valid till send function is called") — worth rereading before adding any new dynamic (non-string-literal) response header anywhere in this codebase.
- **Basic auth over plaintext HTTP.** No TLS on this device; the base64-encoded
  credential is visible to anything that can see LAN traffic. Acceptable under the
  appliance's existing LAN-trust posture (no other endpoint is encrypted either), but
  a real security boundary requires HTTPS, which is out of scope here.
- **CORS is effectively open.** Reflecting any `Origin` means any web page's script
  can issue authenticated requests if it has (or can prompt for) valid credentials —
  the origin check provides no protection by itself; auth is the only gate.
- **The DNS path is no longer lock-free.** `record_store().find()` takes a mutex on
  every query that isn't served by cache/blocklist-before-lookup ordering (local
  table is checked first, before blocklist/cache/forward). Contention is
  effectively zero (single DNS task; the HTTP task's mutations are rare), but the
  "no shared mutable state" narrative from `ARCHITECTURE.md` needed a real update
  here, not just an aside.
- **`max_uri_handlers` is a small, easy-to-undercount budget** — the same shape as
  the Phase 1 socket-budget trap. The next endpoint added anywhere needs this
  re-checked, not just incremented by one.
- **No rate limiting on the mutating routes.** A brute-force attempt against Basic
  auth isn't throttled; acceptable for a LAN appliance without internet-facing
  exposure, worth revisiting if that assumption ever changes.

## Open threads

- **NVS-stored, rotatable admin credentials** were considered and deferred — no
  change-password endpoint exists yet to make that machinery pay for itself.
- **A compile-time CORS origin allow-list** was considered and rejected in favor of
  reflect-any-origin, for reflash-free dev/prod frontend flexibility; revisit if the
  device is ever expected to be internet-reachable.
- **Rate limiting / lockout on repeated auth failures** — not implemented; see
  Gotchas.
- **Phase 6 (hardening & reliability)** is next per `ARCHITECTURE.md`'s
  future-scoping — unrelated to this phase's record-management work.
