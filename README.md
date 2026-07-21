# mini_dns

A minimal ESP32-S3 firmware that connects to Wi-Fi, resolves a runtime-managed set of hostnames over DNS (UDP/53), forwards everything else to an upstream resolver with TTL caching, sinkholes ad/tracker domains, advertises itself via mDNS, and serves an HTTP page + a JSON CRUD API + Prometheus metrics.

Proof-of-concept moving toward a marketable "edge DNS" appliance — no provisioning UI, no OTA, no TLS. Records are NVS-persisted and editable via a Basic-auth-gated CRUD API as of Phase 5, dual-stack (A+AAAA) as of Phase 6, with a secondary-upstream retry on forward timeout and a host-side Unity test suite for the wire-format layer (see below). See [`ARCHITECTURE.md`](ARCHITECTURE.md) for design details, gotchas, and future scoping.

## Prerequisites

- An ESP32-S3 dev board
- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/get-started/index.html) v5.4+ installed and working (this project was built/tested against v5.4.4)
- A USB cable and the board's serial port drivers, if your OS needs them

## Setup

1. **Clone the repo:**
   ```
   git clone https://github.com/RndmCodeGuy20/mini_dns.git
   cd mini_dns
   ```

2. **Create `main/wifi_credentials.h`** — this file is gitignored (it holds real Wi-Fi credentials) and does not exist on a fresh clone. Create it with your own values:
   ```cpp
   #pragma once
   constexpr const char* WIFI_SSID = "your-ssid";
   constexpr const char* WIFI_PASSWORD = "your-password";
   ```

3. **Create `main/admin_credentials.h`** — gitignored, same pattern as above. This is the Basic-auth credential checked on the mutating `POST`/`PUT`/`DELETE /api/records` routes (Phase 5):
   ```cpp
   #pragma once
   constexpr const char* ADMIN_USER = "admin";
   constexpr const char* ADMIN_PASS = "your-password";
   ```

4. **Edit `main/dns_records.h`** with your own hostname → IPv4 mappings. As of Phase 5 this is only the **first-boot seed** — `DNS_RECORDS_DEFAULTS` is loaded into NVS once, then the live table lives there and is managed via the CRUD API below, not by reflashing:
   ```cpp
   constexpr std::array<dns_record_t, N> DNS_RECORDS_DEFAULTS = {{
       {"myhost.loc", {192, 168, 1, 100}},
       // ...
   }};
   ```
   Avoid the `.local` TLD for anything you intend to reach from a phone/laptop browser — see the mDNS gotcha below. (The device itself is always reachable at `edge-dns.local` regardless of what TLD your records use — see Phase 4.) This seed table is IPv4-only; an AAAA address for a seeded name can be added afterward through the CRUD API (Phase 6, below) once the device has booted.

## Building and flashing

```
source $IDF_PATH/export.sh   # e.g. ~/esp/esp-idf/export.sh
idf.py set-target esp32s3
idf.py build
idf.py -p <PORT> flash monitor
```

Finding `<PORT>`:
- macOS: `ls /dev/tty.usbserial-* /dev/tty.usbmodem*`
- Linux: usually `/dev/ttyUSB0` or `/dev/ttyACM0`

On boot you should see log lines for Wi-Fi connecting (with the assigned IP), the DNS server binding to port 53, and the HTTP server starting on port 80. Exit the serial monitor with `Ctrl+]`.

## Testing

Replace `<esp32-ip>` with the IP logged on boot:

```
dig @<esp32-ip> <your-hostname>       # DNS resolution — record store, cache, or forwarded upstream
dig @<esp32-ip> doubleclick.net       # sinkholed (0.0.0.0 / NXDOMAIN) if on the ad-block list
curl http://<esp32-ip>/               # HTML dashboard
curl http://<esp32-ip>/api/records    # JSON record list
curl http://<esp32-ip>/api/blocklist  # JSON blocklist status + running block count
curl http://<esp32-ip>/metrics        # Prometheus plaintext metrics
curl http://edge-dns.local/           # same dashboard, resolved via mDNS instead of raw IP

# Record management (Phase 5) — POST/PUT/DELETE require Basic auth
curl -u admin:<your-password> -X POST -d '{"host":"foo.loc","ip":"192.168.1.99"}' \
  http://<esp32-ip>/api/records
curl -u admin:<your-password> -X PUT -d '{"host":"foo.loc","ip":"192.168.1.100"}' \
  http://<esp32-ip>/api/records
curl -u admin:<your-password> -X DELETE -d '{"host":"foo.loc"}' \
  http://<esp32-ip>/api/records

# Dual-stack records (Phase 6) — "ip" and "ipv6" are each optional, but a
# create/update needs at least one; either or both together are fine
curl -u admin:<your-password> -X POST \
  -d '{"host":"dual.loc","ip":"192.168.1.99","ipv6":"2001:db8::1"}' \
  http://<esp32-ip>/api/records
dig @<esp32-ip> AAAA dual.loc          # answered locally, not forwarded
dig @<esp32-ip> AAAA foo.loc           # v4-only record: NOERROR, no answer (NODATA) — not NXDOMAIN
```

## Running host tests

The pure DNS wire-format functions (`main/dns_wire.h/.cpp`) have no FreeRTOS/lwIP
dependency, so they're covered by a Unity test suite that builds and runs on the
host — no board, no QEMU (Phase 6):

```
source $IDF_PATH/export.sh
idf.py --preview set-target linux -C host_test build
./host_test/build/host_test.elf
```

Exits 0 with `24 Tests 0 Failures` on success — a nonzero exit is Unity's failure
count, so this is CI-friendly as-is.

## Known gotchas (see ARCHITECTURE.md for full detail)

- **`.local` hostnames won't resolve from a phone/laptop browser.** `.local` is reserved for mDNS (RFC 6762); client OS resolvers intercept it before it ever reaches this device's DNS server. `dig`/`nslookup` work fine since they bypass that OS-level special-casing. Use a different TLD (e.g. `.loc`, `.test`) for anything you need a real browser to resolve. The device itself is always reachable at `edge-dns.local` via a real mDNS responder (Phase 4) — that's a separate mechanism from your own records.
- **Forwarding, not true recursion.** Anything not in the record store or the ad-block list is forwarded to an upstream resolver (`1.1.1.1` by default) and cached — not resolved by walking the root servers. As of Phase 6, a timed-out query is retried once against a secondary (`1.0.0.1`) before giving up; only if both time out does the client get SERVFAIL (after up to ~4s total).
- **Metrics run for the life of the device.** `/metrics` counters reset only on reboot — there's no zero/reset endpoint.
- **Basic auth runs over plaintext HTTP.** There's no TLS on this device, so credentials for the mutating `/api/records` routes are base64-encoded, not encrypted. Fine on a trusted LAN, not a real security boundary.
- **CORS is effectively open.** The mutating routes reflect back whatever `Origin` a request sends (browsers disallow a wildcard alongside credentialed requests) — protection comes entirely from the Basic-auth check, not from origin filtering.
