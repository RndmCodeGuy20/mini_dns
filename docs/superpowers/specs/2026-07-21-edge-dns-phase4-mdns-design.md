---
tags: [decision, feature, arch]
status: active
supersedes: ""
related: []
complexity: low
---

# Edge DNS — Phase 4: mDNS responder

## What

Adds a multicast-DNS responder (`espressif/mdns` managed component) so the
appliance advertises itself on the LAN as `edge-dns.local`, plus an `_http._tcp`
service instance ("edge DNS") pointing at the existing dashboard on port 80.
Advertises both A and AAAA records — the latter requires enabling IPv6
link-local addressing on the STA netif, which the appliance did not do before
this phase.

This is Phase 4 of the "edge DNS" vision, following forwarding+cache (Phase 1),
ad-block (Phase 2), and the `/metrics` endpoint (Phase 3).

## Why

- **The problem:** every prior phase made the appliance more capable, but it
  remained reachable only at a raw DHCP-assigned IP. `GET /`, the JSON APIs, and
  `/metrics` all require knowing that IP out of band. mDNS solves exactly this —
  standard, zero-config LAN name resolution via `dns-sd`/Bonjour/`avahi-browse`
  — without adding any persistence, provisioning, or auth surface.
- **A genuinely different mechanism from the unicast resolver, run alongside
  it, not instead of it.** The DNS task (`dns_server.cpp`) answers unicast
  queries on UDP/53 for `DNS_RECORDS` (now on the `.loc` TLD) plus forwarded/
  cached/ad-blocked queries. mDNS answers *multicast* queries on
  224.0.0.251/ff02::fb:5353 for `edge-dns.local` specifically. These do not
  overlap or compete; the `mdns` component owns its own task and socket(s), the
  same footing as `esp_http_server`.
- **Device self-advertisement only, not delegating the `.loc` record table as
  `.local` hosts.** The `.local` gotcha (`ARCHITECTURE.md`) was already solved
  by moving `DNS_RECORDS` off `.local` onto `.loc` in an earlier step — this
  phase isn't rescuing that. Advertising each record as a delegated `.local`
  host (`mdns_delegate_hostname_add`) was considered but rejected as a larger,
  separate feature (see Open threads); this phase's blast radius stays to "make
  the appliance itself discoverable."
- **IPv4 + IPv6, chosen deliberately over IPv4-only:** the rest of the
  appliance (unicast resolver, cache, forwarder) is IPv4-only by inheritance
  from `dns_record_t`'s `std::array<uint8_t, 4>`, but mDNS is commonly consumed
  by clients (macOS, Linux) that prefer AAAA when both are present. Advertising
  both costs one small, self-contained addition to `wifi_connect.cpp`
  (SLAAP link-local + a log-only `GOT_IP6` handler) and is kept strictly
  non-blocking so it cannot regress IPv4 boot readiness if IPv6 is unavailable
  on a given network.
- **`ESP_ERROR_CHECK` for every mDNS setup call, not log-and-continue:** these
  are one-shot startup calls with no meaningful degraded mode, matching the
  codebase's existing split (documented in `ARCHITECTURE.md`) between
  `ESP_ERROR_CHECK`'d startup calls and logged-and-continued per-packet calls.

## How (key parts)

### New dependency
`espressif/mdns` is not bundled in this project's ESP-IDF v5.4 checkout, so
`main/idf_component.yml` declares it (`espressif/mdns: "^1.8"`) as a managed
component, resolved by `idf.py reconfigure`/`build`.

### New module: `mdns_responder.h`/`.cpp`
`mdns_responder_start()` — same one-shot startup shape as `http_server_start()`
(the `mdns` component runs its own internal task, so this call configures and
returns): `mdns_init()` → `mdns_hostname_set("edge-dns")` →
`mdns_instance_name_set("edge DNS")` → `mdns_service_add(nullptr, "_http",
"_tcp", 80, ...)`. Called from `main.cpp` after `http_server_start()`. The
`mdns` component auto-advertises whatever A/AAAA addresses the STA netif
currently holds — no explicit address wiring needed in this module.

### IPv6 link-local (`wifi_connect.cpp`)
`esp_netif_create_default_wifi_sta()`'s return value (previously discarded) is
now kept (`s_sta_netif`). `WIFI_EVENT_STA_CONNECTED` triggers
`esp_netif_create_ip6_linklocal(s_sta_netif)` (SLAAC); a new `IP_EVENT_GOT_IP6`
handler logs the resulting address for boot-log visibility, matching the
existing IPv4 "connected, IP:" log. Neither gates `WIFI_CONNECTED_BIT` — the
existing IPv4 `IP_EVENT_STA_GOT_IP` remains the sole boot-readiness signal, so
a network without IPv6 (or a slow SLAAC) cannot stall or break boot.

### Socket budget
`CONFIG_LWIP_MAX_SOCKETS=16` (Phase 1/2 headroom). Current usage: httpd (7 +
3 reserved = 10) + DNS listen (1) + forwarder upstream (1) = 12. mDNS adds
~2 multicast sockets (v4 + v6) → ~14. Headroom holds; **no sdkconfig change**
this phase. Per the existing gotcha, this is the first thing to re-check if
`mdns_init()`/`httpd_start()` aborts at boot.

## Gotchas

- **AAAA advertisement depends on the network actually offering IPv6.** On an
  IPv4-only LAN, `esp_netif_create_ip6_linklocal` still succeeds (link-local
  doesn't need a router), so `edge-dns.local` should still get an AAAA in
  practice — but this hasn't been tested against a network with IPv6
  disabled at the switch/AP level, only against IPv6-capable ones (verify
  during hardware bring-up).
- **`mdns_service_add`'s port (80) is a hardcoded duplicate of
  `http_server.cpp`'s implicit default port** — if the HTTP server's port ever
  changes, this must be updated by hand; there's no shared constant today.
- **No `.local` record delegation.** Clients that only ever query `.local`
  (see the pre-existing `.local`/Apple-interception gotcha in
  `ARCHITECTURE.md`) still cannot resolve `test.loc`/`router.loc`/etc. via
  mDNS — only `edge-dns.local` itself is mDNS-resolvable. That gotcha is
  unchanged by this phase; see Open threads.

## Open threads

- **Delegating `DNS_RECORDS` as `.local` hosts** (`mdns_delegate_hostname_add`)
  was considered and explicitly deferred — a genuinely separate feature (mDNS
  answering for the static record table, not just the device itself) with its
  own design questions (does it duplicate the ad-block/cache path? what TTL?).
- **No mDNS-advertised TXT metadata beyond a bare `path=/`** — could later
  advertise version, or a `metrics=/metrics` TXT key so tooling can discover
  the Prometheus endpoint without hardcoding the path.
- **NVS-backed persistence + real add/edit/delete API** remains the next
  natural phase per `ARCHITECTURE.md`'s future-scoping list, unrelated to this
  phase's mDNS work.
