#pragma once

// Brings up the SoftAP captive-portal provisioning flow: AP "edge-dns-setup"
// (open, no password — physical proximity is the access control here),
// a captive DNS responder that answers every A query with the AP's own IP,
// and an httpd instance serving /scan, /provision, and a wildcard portal
// page. Called from main.cpp only when wifi_connect_sta() couldn't get an
// IP within its boot-time timeout. Returns after spawning the DNS task and
// httpd instance — both run independently, same convention as
// dns_server_start().
void wifi_provision_start();

// Starts a background task that watches GPIO0 (BOOT) for a ~5s hold and, on
// seeing one, wipes the stored Wi-Fi config (esp_wifi_restore()) and
// reboots — the recovery path for "provisioned with the wrong password" when
// there's no cable handy. STA mode only: in AP mode the provisioning portal
// already *is* the recovery path, and there's no reason to contend with
// anything else that might want GPIO0.
void factory_reset_watch_start();
