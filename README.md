# mini_dns

A minimal ESP32-S3 firmware that connects to Wi-Fi, resolves a small hardcoded set of hostnames over DNS (UDP/53), and serves an HTTP page + JSON API showing that same record table.

Proof-of-concept — no persistence, no provisioning UI, no OTA, no runtime record editing, no auth, no upstream DNS forwarding. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for design details, gotchas, and future scoping.

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

3. **Edit `main/dns_records.h`** with your own hostname → IP mappings. The table committed to this repo reflects the original author's test network — replace it with entries meaningful to your own LAN:
   ```cpp
   constexpr std::array<dns_record_t, N> DNS_RECORDS = {{
       {"myhost.loc", {192, 168, 1, 100}},
       // ...
   }};
   ```
   Avoid the `.local` TLD for anything you intend to reach from a phone/laptop browser — see the mDNS gotcha below.

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
dig @<esp32-ip> <your-hostname>       # DNS resolution
curl http://<esp32-ip>/               # HTML dashboard
curl http://<esp32-ip>/api/records    # JSON record list
```

## Known gotchas (see ARCHITECTURE.md for full detail)

- **`.local` hostnames won't resolve from a phone/laptop browser.** `.local` is reserved for mDNS (RFC 6762); client OS resolvers intercept it before it ever reaches this device's DNS server. `dig`/`nslookup` work fine since they bypass that OS-level special-casing. Use a different TLD (e.g. `.loc`, `.test`) for anything you need a real browser to resolve.
- **No upstream DNS forwarding.** This is a leaf resolver — anything not in `DNS_RECORDS` gets NXDOMAIN. If you point a device's DNS settings at this appliance, that device loses normal internet DNS resolution until you point it back.
