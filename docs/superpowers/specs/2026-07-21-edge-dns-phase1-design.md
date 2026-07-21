---
tags: [decision, feature, arch]
status: active
supersedes: ""
related: []
complexity: high
---

# Edge DNS — Phase 1: Forwarding Resolver + TTL Cache

## What

`mini_dns` today is a leaf resolver: it answers only a compile-time static table
(`DNS_RECORDS`) and returns NXDOMAIN for everything else. This phase adds upstream
DNS forwarding with caching, so pointing a client's DNS at the device gives it working
general internet resolution — while the existing static table keeps precedence for its
own names.

This is Phase 1 of a larger "edge DNS" vision (configurable ad-block, metrics/OTEL export,
mDNS). Those are separate subsystems with their own specs; this phase builds the resolver
+ cache foundation they'll each hook into.

## Why

- **The problem:** every domain not in `DNS_RECORDS` is NXDOMAIN. A client that adopts this
  device as its DNS server loses general internet access — the single biggest blocker to
  calling this an "edge DNS" rather than a toy.
- **Forwarding, not true recursion:** "recursive DNS resolution" in the original ask is
  implemented here as forward-to-upstream-and-cache (the dnsmasq/Pi-hole model), not true
  iterative resolution from the root servers. True recursion is large, stateful, and strictly
  slower/costlier than asking a nearby upstream (1.1.1.1/8.8.8.8) that already did the work —
  rejected as disproportionate to the value for an MCU-class device.
- **`select()` event loop, not synchronous forward-and-wait:** the current design blocks on a
  single `recvfrom` per iteration. A synchronous "forward and block for the upstream reply"
  approach would stall every other client for the upstream's round-trip. Rejected in favor of
  a non-blocking `select()` loop over the listen + upstream sockets, correlating replies via
  an in-flight table — this is what resolves the transaction-ID collision problem the original
  ARCHITECTURE.md flagged as unsolved ("two independent ID spaces").
- **Single-task ownership, no mutex:** keeping the whole resolution pipeline (local table →
  cache → forwarder) in one FreeRTOS task preserves the codebase's existing "no shared mutable
  state" property instead of introducing locking between DNS and HTTP tasks.

## How (key parts)

### Resolution order (per incoming query)
1. Local static table (`find_dns_record`, existing, untouched) — authoritative, always wins.
2. Cache hit (fresh) → serve, with client's txn ID spliced in.
3. Miss → forward to upstream, correlate, cache, relay.

### Concurrency: `select()` loop + in-flight query table
`dns_server_task` becomes a `select()` loop over two sockets: the existing UDP/53 listener,
and a new UDP client socket to the upstream resolver. A fixed-size in-flight table (32–64
slots) tracks queries sent upstream but not yet answered. Each outstanding query is assigned
an **upstream transaction ID whose low bits encode the table slot index** — this gives O(1)
match on reply without a linear scan, and sidesteps ID collisions between the client-facing
and upstream-facing ID spaces. Each slot carries a deadline; `select()`'s timeout parameter
doubles as the mechanism for expiring stale slots (upstream never replied → SERVFAIL to
client, slot freed). A full table means immediate SERVFAIL — no blocking, no queueing.

### Cache
- **Key:** (lowercased qname, qtype). **Value:** raw upstream answer bytes, min-TTL across
  its RRs, insertion timestamp.
- **Expiry:** whole-entry eviction at `now - inserted >= min_TTL`. Per-RR TTL decrement on
  every hit was considered and deferred — v1 re-serves the original TTL each hit, bounded by
  entry-level expiry; correct enough for a resolver whose clients re-query at their own pace.
- **Negative caching:** NXDOMAIN/NODATA cached too, with a capped TTL (RFC 2308), so a
  repeated miss doesn't repeatedly hit upstream.
- **Capacity:** sized for PSRAM (device confirmed to have it, though not yet enabled in the
  build) — a few thousand entries. LRU eviction when full.

### Module decomposition
`dns_server.cpp` was already flagged as the natural home for growing complexity; splitting
it now keeps each piece independently testable:
- `dns_wire.h/.cpp` — pure wire-format functions, no I/O. Existing `parse_dns_header`,
  `parse_question_name`, `read/write_uint*_be`, response builders move here unchanged, plus
  two new functions: `skip_name` (walks a name in the *answer* section, where — unlike the
  question section — compression pointers are common and must be followed to find the next
  RR) and `answer_min_ttl` (walks answer RRs to compute the cache entry's TTL).
- `dns_cache.h/.cpp` — `lookup` / `insert` / `sweep_expired`. Single owner (the DNS task).
- `dns_forwarder.h/.cpp` — upstream socket, in-flight table, slot allocation/ID-encoding,
  deadline expiry.
- `dns_server.cpp` — retained as the orchestrating `select()` loop only.

### Config
Compile-time `constexpr` for v1 (upstream IP(s), cache capacity, upstream timeout) —
consistent with the project's existing style and its explicit non-goal of runtime
configuration until an add/edit/delete API exists.

### PSRAM
Chip supports it; the current build has it disabled (`# CONFIG_SPIRAM is not set`). This
phase enables it in `sdkconfig.defaults` and adds a boot-time log of detected PSRAM size, to
confirm the quad-vs-octal mode matches the actual module before relying on its capacity.

## Gotchas

- **PSRAM mode (quad vs octal) is module-specific** — wrong mode can fail to init or silently
  underperform. The boot-time size log is the confirmation step; if it doesn't match
  expectations, the cache degrades to SRAM-only capacity rather than failing outright.
- **In-flight table exhaustion under upstream slowness/loss** must fail closed (SERVFAIL), not
  block the listener — this is the whole reason for the `select()` rewrite instead of a
  simpler synchronous forward.
- **Local table precedence must not regress** — the existing `find_dns_record` check has to
  run before any cache/forward path, or a static entry could be shadowed by a stale cached
  upstream answer for the same name.
- **Negative-cache TTL must be capped independently of upstream's SOA/negative TTL** (RFC
  2308 guidance) — an upstream returning an absurdly long negative TTL shouldn't lock out a
  name indefinitely once conditions change.

## Open threads

- Per-RR TTL decrement on cache hits (more RFC-correct, deferred as unnecessary complexity
  for v1).
- True recursive (root-walking) resolution as a possible future mode — not planned, listed
  only because "recursive DNS" was the original phrasing and the fork is worth remembering.
- Phase 2 (ad-block), Phase 3 (Prometheus `/metrics`), Phase 4 (mDNS) each get their own
  spec once this phase is verified on hardware. See `ARCHITECTURE.md` future-scoping notes.
