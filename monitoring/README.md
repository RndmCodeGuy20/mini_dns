# mini_dns monitoring stack

Prometheus + Grafana for the device's `/metrics` endpoint. Runs on your dev
machine, not the ESP32 — the ESP32 is just a scrape target.

## Setup

1. Find the device's LAN IP from its boot log (or `edge-dns.local` if your
   local resolver forwards mDNS, which most don't by default).
2. Edit `prometheus/prometheus.yml`, replace `<esp32-ip>` with that IP.
3. From this directory:
   ```
   docker compose up -d
   ```
4. Prometheus: http://localhost:9090 — check Status > Targets, `mini_dns`
   job should be `UP`.
5. Grafana: http://localhost:3000 — login `admin`/`admin`, you'll be
   prompted to change it on first login. Dashboard "mini_dns" is
   auto-provisioned under the `mini_dns` folder.

## Notes

- If the device's IP changes (DHCP lease renewal), re-edit
  `prometheus/prometheus.yml` and `docker compose restart prometheus`.
  A static DHCP reservation on your router avoids this.
- Grafana's datasource and dashboard are provisioned from files
  (`grafana/provisioning/`) — don't hand-edit them in the UI, changes
  won't persist across container recreation.
