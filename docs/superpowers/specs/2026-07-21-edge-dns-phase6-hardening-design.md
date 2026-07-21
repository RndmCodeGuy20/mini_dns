---
tags: [decision, feature, arch]
status: active
supersedes: ""
related: []
complexity: medium
---

# Edge DNS — Phase 6: Hardening & reliability

## What

Three correctness/resilience gaps closed against what Phases 1–5 already shipped:
local records can now hold an A, an AAAA, or both (dual-stack); a wrong-family query
against an existing name returns the RFC-correct NODATA instead of NXDOMAIN; a
forwarded query that times out against the primary upstream is retried once against
a secondary before SERVFAIL; and the pure wire-format functions in `dns_wire.cpp`
gained a host-side Unity test suite.

This is Phase 6 of the "edge DNS" vision, bundled as one phase because none of the
three touch the concurrency model or add new attack surface — unlike Phase 5, this
phase rounds out correctness/resilience of what already shipped rather than adding a
new capability surface.

## Why

- **The problem:** local records were IPv4-only, so an AAAA query for a local name
  fell through to NXDOMAIN — wrong for any dual-stack client, which then treats the
  name as nonexistent instead of falling back to A. Forwarding had a single
  hardcoded upstream with no failover: one unreachable resolver meant every non-local
  query SERVFAILed. And every phase since Phase 1 had shipped with zero automated
  tests, verified only by flashing hardware and reading a serial log.
- **Dual-stack, not "replace A with AAAA":** a name can legitimately need both — the
  household router at `router.loc` might answer A only, while a service meant to be
  reached over IPv6 needs AAAA only, and some hosts want both. `DnsRecordEntry` holds
  `std::optional<std::array<uint8_t,4>> ipv4` and
  `std::optional<std::array<uint8_t,16>> ipv6` side by side rather than a single
  tagged-union address — never both empty (`create()`/`update()` reject that), but
  either one alone is fine.
- **NODATA over NXDOMAIN for a wrong-family match.** The distinction that matters to
  a dual-stack client: NXDOMAIN says "give up on this name entirely," NODATA says
  "this name exists, just not for what you asked" — the client then correctly leaves
  the other family's query alone rather than treating the whole name as gone. This
  reverses Phase 1–5's stated simplification (`ARCHITECTURE.md`'s old "NXDOMAIN not
  NODATA" gotcha) now that a name can genuinely have only one family — the
  simplification stops being harmless once that's true.
- **`DnsRecordStore::find()` returns the whole entry, not one address.** The old
  signature (`std::optional<std::array<uint8_t,4>>`) can't express "name exists but
  has no AAAA" — only "found" or "not found." Returning `std::optional<DnsRecordEntry>`
  by value (same "copy, not a pointer" contract Phase 5 established) lets
  `dns_server.cpp` distinguish all three cases the resolution path needs: matching
  family present, name exists but wrong family (NODATA), name absent entirely (falls
  through to blocklist/cache/forward).
- **On-timeout retry to a secondary, not dual-send or sticky failover.** Considered
  and rejected: sending to both upstreams simultaneously and taking whichever answers
  first (lower latency on the happy path, but doubles upstream traffic and needs a
  second correlation path); tracking upstream health and switching the *active*
  upstream after N consecutive failures (avoids retry latency on individual queries,
  but adds persistent health state and a recovery-detection problem neither upstream
  actually needs solved at LAN scale). A single retry on timeout is the smallest
  change that survives one upstream being briefly unreachable, reuses the existing
  socket and transaction-ID scheme untouched, and adds no state that outlives a
  single query.
- **Same operator, second address — not two independent resolvers.** The secondary
  (`1.0.0.1`) is Cloudflare's other anycast address, not a different provider. This
  is about surviving one address being unreachable (routing hiccup, that anycast
  address specifically down), not diversifying trust away from a single operator —
  see Open threads.
- **ESP-IDF's `linux` target + bundled Unity, not a standalone host build.** Keeps
  the test suite inside the same build system as the firmware (same `idf.py`
  invocations, same component-registration idiom) rather than introducing a second,
  parallel CMake/toolchain setup that could drift from what actually ships.
  `dns_wire.cpp` has zero FreeRTOS/lwIP dependency (a property already established
  by the Phase 1 module split), so it links against Unity and runs as a native
  process — no QEMU, no board.

## How (key parts)

### `dns_wire.h`/`.cpp`: AAAA and NODATA builders
`DNS_TYPE_AAAA = 28` (was a bare literal inside `qtype_to_string`). The RR-writing
tail shared by `build_a_record_response`/new `build_aaaa_record_response` is
factored into a private `build_address_record_response(rtype, rdata, rdata_len, ...)`
so the two can't drift on the surrounding fixed fields (name-pointer, class, TTL).
New `build_nodata_response` is `build_nxdomain_response`'s twin with
`rcode = DNS_RCODE_NOERROR` instead of `DNS_RCODE_NXDOMAIN`, `ancount = 0` either way.

### `dns_record_store.h`/`.cpp`: dual-stack entries
`DnsRecordEntry` gains `std::optional<std::array<uint8_t,4>> ipv4` and
`std::optional<std::array<uint8_t,16>> ipv6` in place of the single `ip` field.
`find()` returns `std::optional<DnsRecordEntry>` (whole-entry copy). `create()`/
`update()` take both optionals and reject an all-`nullopt` pair
(`DnsRecordStoreResult::kNoAddress`, new enum value); `update()` is a full replace of
the address set (PUT semantics), not a per-family patch. NVS serialization stays
backward-compatible: one `hostname=A.B.C.D` and/or `hostname=<ipv6>` line per record
(family detected on read by the presence of `:`, via `inet_pton`/`inet_ntop`), so a
pre-Phase-6 v4-only blob loads unchanged — no migration step, no format version.

### `dns_server.cpp`: resolution path
`record_store().find(*qname)` now returns the whole entry; the qtype dispatch became
three-way: `qtype==A && ipv4` → `build_a_record_response`; `qtype==AAAA && ipv6` →
`build_aaaa_record_response`; anything else (right qtype, wrong family present, or an
unrelated qtype) → `build_nodata_response`. The blocklist sinkhole path gained the
matching AAAA case (`::` in place of `0.0.0.0`), with NODATA replacing its own
previous NXDOMAIN fallback for other qtypes.

### `dns_forwarder.h`/`.cpp`: secondary-upstream retry
`primary_addr_`/`secondary_addr_` replace the single `upstream_addr_`. `forward()`'s
send logic is factored into `send_to_upstream(slot, upstream, upstream_txn_id)`,
reused by both the first attempt (primary) and the retry (secondary) so they can't
drift on wire format. `in_flight_slot_t` gains `uint8_t attempt` (0 = primary only, 1
= secondary tried). `reap_expired()` returns `reap_result_t{expired, retried}`: a
slot at `attempt==0` past its deadline gets one `send_to_upstream(secondary_addr_,
same_txn_id)`, a fresh deadline, and stays occupied (counted in `retried`, not
`expired`); only a slot that times out at `attempt==1` (or whose secondary send
itself fails) is finally reported in `expired`. `handle_upstream_readable()`'s source
check now accepts a reply from either address — the slot/generation match in the
transaction ID is what actually authenticates a reply, the source-address check is
just "did this come from an upstream we asked," and a late primary reply after a
retry already fired is still a legitimate answer for that slot.

### Metrics
New `dns_upstream_retries_total` counter (same shape/pattern as
`dns_upstream_timeouts_total`): incremented once per slot moved to the secondary.
`dns_upstream_timeouts_total`'s meaning narrows to *final* give-ups only (both
upstreams exhausted) — a query that succeeds on the secondary is no longer double-
counted as a timeout.

### `http_server.cpp`: dual-stack JSON API
`GET /api/records` emits `{"host", "ip"?, "ipv6"?}` per entry — `ip` unchanged for
frontend backward compatibility, `ipv6` added, absent families omitted rather than
emitted as `null`. `parse_record_request` reads each of `ip`/`ipv6` if present
(new `parse_ipv6` via `inet_pton`) and 400s if neither is valid/present. `PUT`
replaces the stored address set with exactly what was supplied (matching the store's
full-replace semantics above).

### Host tests: `host_test/`
A second ESP-IDF project (sibling to the firmware's `CMakeLists.txt`, not nested
under `main/`) targeting `linux`: `main/CMakeLists.txt` compiles
`../../main/dns_wire.cpp` directly (the exact file that ships, not a copy) alongside
`test_dns_wire.cpp`, `REQUIRES unity`. Tests use ESP-IDF's `TEST_CASE`/
`unity_run_all_tests()` auto-registration pattern. `app_main()` calls
`exit(UNITY_END())` rather than returning — see Gotchas.

## Gotchas

- **The `linux` target's FreeRTOS port never returns from `vTaskStartScheduler()` —
  `app_main()` returning doesn't end the process.** Caught immediately on first run:
  the binary printed all 24 `PASS`/`FAIL` lines and the `Tests`/`Failures` summary,
  then hung forever instead of exiting. Fixed by having `app_main()` call
  `exit(UNITY_END())` explicitly — which also turns Unity's failure count into a real
  process exit code, making `./host_test.elf; echo $?` (or a CI step) meaningful
  without scraping log output.
- **RR byte-layout is 2 (name pointer) + 10 (`DNS_ANSWER_RR_FIXED_SIZE`: type+class+
  ttl+rdlength) + rdata — not 12 including rdlength inside the fixed block at some
  other offset.** Two of the new tests were themselves wrong on first write (rdlength
  computed 2 bytes early, landing inside the TTL field) and one buffer was undersized
  by exactly the 2-byte name pointer — caught by an actual failing `TEST_ASSERT`, not
  by inspection. Worth re-deriving this offset math from scratch rather than
  copy-adjusting an existing test when adding another RR-shaped assertion.
- **`build_nodata_response` was declared in `dns_wire.h` and used in `dns_server.cpp`
  before it was ever implemented in `dns_wire.cpp`** — caught only at host-test link
  time (`undefined symbols`), not by the ESP32-S3 firmware build, since that build
  happened to link successfully via a different path at the point the gap existed.
  A concrete argument for having the host-test link step in the loop early, not just
  at the end.
- **`DnsRecordStore::create()`/`update()` reusing `kNotFound` for "no address
  supplied" would have been actively confusing** (a `create()` "not found"?) — added
  a dedicated `kNoAddress` enum value instead of overloading an existing one for a
  different failure mode.
- **Still a single operator underneath, not failover across providers** — see Open
  threads.

## Open threads

- **Cross-operator secondary** (e.g. a non-Cloudflare resolver as the fallback,
  instead of Cloudflare's other anycast address) was considered and deferred — this
  phase is about surviving one address being transiently unreachable, not building
  provider-diversity into the trust model; revisit if Cloudflare-wide outages become
  a real concern for this device's deployment.
- **Per-RR TTL for dual-stack entries** — a record's A and AAAA currently share the
  same fixed 60s answer TTL (`build_address_record_response`'s hardcoded constant,
  unchanged since Phase 1); independent TTLs per family were never a stated
  requirement and would only matter if local records grow real expiry semantics.
- **Automated tests cover `dns_wire.cpp` only** — the DNS/HTTP task logic,
  `DnsRecordStore`'s NVS round-trip, and `DnsForwarder`'s retry/timeout state
  machine are still verified only by flashing hardware. Extending coverage there
  needs fakes for sockets/NVS that the wire-format layer's pure functions don't;
  not undertaken this phase.
- **Phase 7 (leaving the dev bench)** is next per `ARCHITECTURE.md`'s future-scoping
  — unrelated to this phase's hardening work.
