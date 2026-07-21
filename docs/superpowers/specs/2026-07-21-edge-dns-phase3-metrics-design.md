---
tags: [decision, feature, arch]
status: active
supersedes: ""
related: []
complexity: medium
---

# Edge DNS — Phase 3: Metrics endpoint

## What

Adds `GET /metrics` in Prometheus plaintext exposition format to the existing
`esp_http_server`, exposing query counts, cache hit/miss, forwarding/upstream
outcomes, SERVFAIL count, ad-block total, upstream latency (as a histogram), and
live cache/in-flight occupancy. Pull model, scraped by an external Prometheus
instance — no OTLP push client, per `ARCHITECTURE.md`'s future-scoping note.

This is Phase 3 of the "edge DNS" vision. Both Phase 1 and Phase 2's design docs
named this phase and its expected content ahead of time.

## Why

- **The problem:** Phase 1 (forwarding + cache) and Phase 2 (ad-block) both run
  entirely inside the DNS task's `select()` loop with no visibility from outside the
  device's serial log. There is no way to see cache hit rate, upstream health, or
  block volume over time without watching `idf.py monitor`.
- **Where the counters actually live:** `DnsCache` and `DnsForwarder` are `static`
  locals owned solely by the DNS task (`dns_server.cpp`), by design, with no mutex.
  The HTTP task that would serve `/metrics` runs independently and cannot safely
  read their internals directly. `DnsBlocklist` already solved this exact problem
  for its one runtime counter (`blocks_total_`, a plain `std::atomic<uint32_t>`,
  Phase 2) — this phase generalizes that pattern into a dedicated module instead of
  duplicating it once per class.
- **A new `DnsMetrics` singleton, not per-class atomic accessors:** centralizes every
  counter/gauge/histogram in one small, HTTP-task-readable module
  (`dns_metrics.h/.cpp`), rather than scattering atomic fields and getters across
  `DnsCache` and `DnsForwarder` and exposing their otherwise-private state globally.
  The DNS task calls `inc_*()`/`observe_*()`/`set_*()` inline at each decision point
  it already makes; the HTTP handler calls a single `snapshot()`.
- **`uint32_t`, not `uint64_t`, for every atomic:** the ESP32-S3's Xtensa LX7 core
  has no native 64-bit atomic instructions. `std::atomic<uint64_t>` on this target
  falls back to libatomic's lock-based implementation, which would reintroduce a
  lock into what is otherwise a deliberately lock-free cross-task read path — the
  exact property Phase 2 called out as worth preserving. A 32-bit counter wrapping
  after ~4B events is an acceptable trade for a LAN-scale device scraped by
  Prometheus, which already tolerates counter resets across `rate()` windows.
- **Histogram, not a bare sum+count, for upstream latency:** a bare `_sum`/`_count`
  pair (2 atomics) only yields an average; a small fixed-bucket histogram (buckets at
  10/50/100/500/1000ms + implicit `+Inf`, 6 buckets + sum + count = 8 atomics) lets
  Prometheus/Grafana compute latency quantiles, which is the more useful signal for
  "is upstream degraded" and costs only a handful of extra words on a PSRAM-equipped
  device.
- **Endpoint-only, no web UI panel:** keeps this phase's blast radius to the new
  module plus small instrumentation call-sites; the existing `GET /` dashboard stays
  records-only. A UI panel is additive later if wanted.

## How (key parts)

### New module: `dns_metrics.h`/`.cpp`
`DnsMetrics` holds one `std::atomic<uint32_t>` per counter (`queries_`,
`local_hits_`, `cache_hits_`, `cache_misses_`, `forwarded_`, `upstream_replies_`,
`upstream_timeouts_`, `servfail_`), a 6-bucket latency histogram
(`std::array<std::atomic<uint32_t>, 6> latency_buckets_` + `latency_sum_ms_` +
`latency_count_`), and two gauges (`cache_entries_`, `inflight_`). All ops use
`memory_order_relaxed`, matching `DnsBlocklist::record_block()`. `snapshot()` reads
every field once into a plain `DnsMetricsSnapshot` struct for the handler to render
from — each field is read independently (not one atomic snapshot of the whole
struct), an acceptable approximation for a metrics scrape target.

`DnsMetrics &metrics()` is a process-wide singleton, same shape as
`DnsBlocklist &blocklist()`.

### Instrumentation call sites (`dns_server.cpp`)
Added inline at the decision points `handle_client_query()`/
`handle_upstream_reply()`/the reap loop already make — no new branches, just a
counter bump alongside each existing one:
- Query parsed → `inc_queries()`.
- Local-table match → `inc_local_hits()`.
- Cache hit → `inc_cache_hits()`; cache miss → `inc_cache_misses()`.
- `forward()` succeeds → `inc_forwarded()`; fails → `inc_servfail()`.
- Upstream reply received → `inc_upstream_replies()` +
  `observe_upstream_latency()`.
- In-flight slot reaped on timeout → `inc_upstream_timeouts()` + `inc_servfail()`.
- End of every `select()` loop iteration → `set_cache_entries(cache.size())` and
  `set_inflight(forwarder.in_flight_count())` (a new `DnsForwarder` accessor, cheap
  linear scan over the 32-slot table).

### Latency measurement (`dns_forwarder.cpp`)
`reply_t` gains a `latency_ms` field. `handle_upstream_readable()` computes it from
the in-flight slot's stored `deadline_ms` and the forwarder's fixed `timeout_ms_`
(`sent_at_ms = deadline_ms - timeout_ms_`) rather than adding a separate
"sent at" field — the deadline already encodes it.

### HTTP: `GET /metrics` (`http_server.cpp`)
A fourth handler on the existing `esp_http_server` instance — no new socket, so
`CONFIG_LWIP_MAX_SOCKETS` (the Phase 1 reboot-loop trap) is untouched. Builds a
`std::string` of Prometheus text (`# HELP`/`# TYPE` per family, one sample line per
counter/gauge, cumulative bucket lines for the histogram), `Content-Type: text/plain;
version=0.0.4`, single `httpd_resp_send`. Pulls `metrics().snapshot()` for
DNS-task-owned counters, and reads `blocklist().blocks_total()`/`blocklist().size()`
directly (no duplication of Phase 2's counter). Cache/in-flight capacity are read
from the existing `constexpr` constants (`DNS_CACHE_CAPACITY`,
`DNS_FORWARDER_MAX_IN_FLIGHT`), not tracked separately.

Exposed series: `dns_queries_total`, `dns_local_hits_total`, `dns_cache_hits_total`,
`dns_cache_misses_total`, `dns_forwarded_total`, `dns_upstream_replies_total`,
`dns_upstream_timeouts_total`, `dns_servfail_total`, `dns_blocked_total`,
`dns_upstream_latency_ms` (histogram), `dns_cache_entries`/`dns_cache_capacity`
(gauge), `dns_inflight_queries`/`dns_inflight_capacity` (gauge),
`dns_blocklist_domains` (gauge).

## Gotchas

- **Snapshot isn't a single atomic operation.** `snapshot()` loads each field
  independently; two fields it returns could in principle be off by one event
  relative to each other if a scrape lands mid-update. Acceptable for a Prometheus
  scrape target — `rate()`/dashboards already smooth over scrape-to-scrape noise —
  but worth remembering if a future consumer expects perfectly consistent snapshots.
- **32-bit counters wrap.** At any plausible LAN query volume this is a
  years-to-centuries event, but `rate()` over a wrapped counter is still correct
  (Prometheus handles counter resets); a raw delta computed by hand would not be.
- **Histogram buckets are non-cumulative internally, cumulative on the wire.**
  `latency_buckets_[i]` counts only observations that landed in that specific
  bucket; the HTTP handler accumulates a running sum while rendering, since
  Prometheus's histogram format requires each `_bucket{le=...}` line to include
  every observation at or below that bound.
- **Latency is derived from the fixed per-forwarder timeout, not a stored send
  timestamp** — correct only because `DnsForwarder` currently has exactly one fixed
  `timeout_ms_` for every in-flight query. If a future phase adds per-query or
  per-upstream timeouts, this derivation breaks and `latency_ms` would need its own
  field on the in-flight slot.

## Open threads

- No web UI panel this phase — `GET /` stays records-only; a live metrics view is
  additive later (fetch `/metrics` or a JSON-shaped stats endpoint).
- No metrics reset/zero endpoint — counters run for the life of the device (until
  reboot); acceptable since NVS persistence for metrics was never in scope.
- mDNS responder (Phase 4) is next per `ARCHITECTURE.md`'s future-scoping list —
  unrelated to this phase's HTTP/metrics work.
