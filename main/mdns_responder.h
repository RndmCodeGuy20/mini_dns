#pragma once

// Starts the mDNS responder (Phase 4) so the appliance is discoverable on
// the LAN as edge-dns.local, plus an _http._tcp service pointing at the
// existing dashboard (see http_server.h). Like esp_http_server, the mdns
// component owns its own internal task — this call just configures and
// starts it, then returns.
void mdns_responder_start();
