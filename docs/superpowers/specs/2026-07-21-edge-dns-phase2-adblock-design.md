---
tags: [decision, feature, arch]
status: active
supersedes: ""
related: []
complexity: medium
---

# Edge DNS — Phase 2: Ad-block

## What

Adds a domain blocklist to the resolver built in Phase 1. A query for a blocked
domain (or any subdomain of one) is sinkholed — `0.0.0.0` for A queries, NXDOMAIN
for everything else — instead of reaching the cache or upstream forwarder. The
blocklist is seeded from a small baked-in default set on first boot, persisted to
NVS, and exposed read-only over HTTP alongside a running block counter.

This is Phase 2 of the "edge DNS" vision scoped in `ARCHITECTURE.md`. Phase 3
(metrics) is expected to read the block counter this phase introduces.

## Why

- **The problem:** the Phase-1 resolver forwards everything it doesn't recognize
  locally, including ad/tracker domains — there is no way to stop resolving a name
  the operator doesn't want resolved.
- **Where it sits in the resolution order:** local table → **blocklist** → cache →
  forward. It must run before the cache/forwarder (a cached or freshly-forwarded
  answer for a blocked name would defeat the block), and after the local table (the
  static table's existing "always wins" invariant from Phase 1 must not regress —
  an operator-configured local record should never be silently sinkholed).
- **Suffix matching, not exact-match:** real ad/tracker infrastructure lives on
  subdomains (`ads.doubleclick.net`, `pixel.doubleclick.net`, …). Exact-match-only,
  while textually what `ARCHITECTURE.md` first sketched, would miss the common
  case and provide little real blocking value. Suffix matching on label boundaries
  (not raw string suffix, to avoid `notdoubleclick.net` false-matching
  `doubleclick.net`) is the standard hosts-list/Pi-hole semantic and is what this
  phase implements instead.
- **NVS storage, read-only HTTP:** runtime persistence (survives reboot) without
  yet building a write API. This keeps the phase's blast radius small — the
  blocklist is populated once at boot (from NVS if present, else from the baked-in
  defaults, which are then persisted) and never mutated afterward. That in turn
  means the Phase-1 "no shared mutable state across tasks, no mutex" property
  extends cleanly: both the DNS task and the HTTP task only *read* the set after
  boot. The one piece of state that does change at runtime — the block counter —
  is a single `std::atomic`, not a structure needing a lock. A write/edit HTTP
  endpoint is deferred; adding one later is a small, additive change (mutate the
  set, call the existing `save_to_nvs()`), not a redesign.

## How (key parts)

### Resolution order
1. Local static table (`find_dns_record`, unchanged) — still authoritative, still
   first.
2. **Blocklist match** (new) — sinkhole and return before touching the cache.
3. Cache hit → serve (unchanged).
4. Miss → forward to upstream (unchanged).

### Matching: suffix walk over an unordered_set
`DnsBlocklist::is_blocked(qname_lower)` tests the full lowercased name, then
repeatedly strips the leftmost label and retests, stopping at the root:
`a.b.doubleclick.net` → `b.doubleclick.net` → `doubleclick.net` → `net`. Each
step is an O(1) `unordered_set` lookup; stripping on label (`.`) boundaries rather
than raw string suffix gives correct semantics for free (`notdoubleclick.net` never
tests as `doubleclick.net`). Blocking a domain implicitly blocks every subdomain of
it — the standard ad-block-list convention.

### Storage: NVS blob, seeded from a baked-in default list
- `main/dns_blocklist_defaults.h` — header-only `constexpr` array of ~15–30
  curated ad/tracker domains, in the same style as `dns_records.h`.
- `DnsBlocklist::load_from_nvs()` — opens NVS namespace `blocklist`, reads a single
  newline-separated blob under key `list`. If the key doesn't exist (first boot),
  populates the in-memory set from the defaults header and calls
  `save_to_nvs()` to persist it, so every subsequent boot loads from NVS instead of
  the compiled-in list. A single blob (rather than one NVS key per domain) sidesteps
  NVS's 15-character key-name limit and keeps the read/write path to one call each.
- `DnsBlocklist::save_to_nvs()` — serializes the current set back to the same blob
  key. Exists now so the load-time seeding path has something to call; a future
  HTTP mutate endpoint calls the same function.

### Counter and cross-task read access
`std::atomic<uint32_t> blocks_total_` increments on every sinkholed query
(`record_block()`, relaxed ordering — an approximate counter for operational
visibility, not a consistency-critical value). `blocks_total()`, `size()`, and a
`const std::unordered_set<std::string>& domains()` accessor are read by the new
`GET /api/blocklist` HTTP handler. This is a deliberate, narrow deviation from
Phase 1's "state lives inside the DNS task" pattern — justified because the set
itself is immutable after boot (only ever read from both tasks) and the counter
is atomic, so no mutex or queue is introduced.

### HTTP: status-only
`GET /api/blocklist` mirrors the existing read-only `GET /api/records` handler
(`http_server.cpp`) — same cJSON pattern, no new response infrastructure:
```json
{ "count": 23, "blocked_total": 104, "domains": ["doubleclick.net", ...] }
```

### Wiring
`blocklist().load_from_nvs()` is called inside `dns_server_start()`, before the
DNS task is created — NVS itself is already initialized earlier by
`wifi_connect()` (`nvs_flash_init()` in `wifi_connect.cpp`), so by the time either
the DNS task or the HTTP server (started after `dns_server_start()` in
`main.cpp`) can touch the blocklist, it's already loaded.

## Gotchas

- **Load-before-serve ordering matters twice over:** the blocklist must be loaded
  before the DNS task starts (or the first queries would race an empty set) *and*
  before `http_server_start()` (or an early `GET /api/blocklist` could observe zero
  domains). Both are satisfied by loading synchronously inside `dns_server_start()`
  ahead of `xTaskCreate`, since `main.cpp` calls `dns_server_start()` before
  `http_server_start()`.
- **Suffix matching must walk label boundaries, not raw string suffixes** — a naive
  `ends_with(qname, blocked)` check would wrongly block `notdoubleclick.net` for a
  blocklist entry of `doubleclick.net`. The label-strip-and-retest approach avoids
  this by construction.
- **Local table precedence must not regress** (same invariant Phase 1 called out
  for cache/forwarder) — the blocklist check sits after `find_dns_record`, so an
  operator's own static record for a name always wins even if that name happens to
  also appear on the blocklist.
- **NVS blob size:** a single blob under one key is simplest, but every save
  rewrites the whole list; fine at the curated-list sizes this phase targets
  (dozens of entries), would need reconsidering if a future phase imports large
  (10k+) third-party lists.

## Open threads

- HTTP write/mutate endpoint (`POST`/`DELETE /api/blocklist`) — deferred; the NVS
  `save_to_nvs()` path exists so this is additive, not a redesign.
- Large third-party list import (SPIFFS/LittleFS-backed, per `ARCHITECTURE.md`'s
  future-scoping) — a different storage tier than NVS, out of scope here.
- Phase 3 (`/metrics`) is expected to expose `blocks_total()` alongside cache/
  forwarder counters once that phase starts.
