# mini_dns monitoring

An OpenTelemetry Collector on your dev machine scrapes the device's `/metrics`
endpoint and pushes it over OTLP to Grafana Cloud (same stack as
health_sync_api). The ESP32 is still just a scrape target, so nothing about
the firmware changes.

## Setup

1. Find the device's LAN IP from its boot log (or `edge-dns.local` if your
   local resolver forwards mDNS, which most don't by default).
2. From this directory, `cp .env.example .env` and fill in:
   - `OTEL_EXPORTER_OTLP_ENDPOINT`: Grafana Cloud OTLP gateway URL.
   - `GRAFANA_OTLP_AUTH`: `Basic <base64 instanceId:token>`. This is the
     value part of health_sync_api's `OTEL_EXPORTER_OTLP_HEADERS`, without
     the `Authorization=` prefix.
   - `MINI_DNS_TARGET`: `<esp32-ip>:80`.
3. `docker compose up -d`
4. `docker compose logs -f otel-collector`: there should be no scrape or
   export errors.
5. In Grafana Cloud Explore, pick the `grafanacloud-*-prom` datasource and
   query `{job="mini_dns"}`.
6. Dashboards > Import > upload `grafana/mini-dns.json`, then pick the
   `grafanacloud-*-prom` datasource.

## Query log

The collector also listens on UDP `54525` (`udp_log` receiver) for one
logfmt line per DNS query from the device, forwarded to Grafana Cloud Loki
(`grafanacloud-logs` datasource, `{service_name="mini_dns"} | logfmt`). The
device sends to `CONFIG_MINI_DNS_QUERY_LOG_TARGET` (set via
`idf.py menuconfig` → mini_dns), which must be this machine's LAN IP and
port `54525`. Lines include the querying client's IP.

## Notes

- If the device's IP changes (DHCP lease renewal), update `MINI_DNS_TARGET`
  in `.env` and run `docker compose up -d`. A static DHCP reservation on
  your router avoids this.
- `.env` holds the Grafana Cloud token and is gitignored.
- The dashboard in Cloud isn't provisioned from this file. After editing
  `grafana/mini-dns.json`, re-import it, or export from the UI back into
  the file.
