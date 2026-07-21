#include "mdns_responder.h"

#include "esp_check.h"
#include "mdns.h"

// One-shot startup configuration, same "panic on failure" style as the
// other *_start() calls (esp_wifi_*, httpd_start) — there's no meaningful
// degraded mode if the responder fails to come up, so fail loudly and
// early rather than limping on silently undiscoverable.
void mdns_responder_start()
{
    ESP_ERROR_CHECK(mdns_init());
    ESP_ERROR_CHECK(mdns_hostname_set("edge-dns")); // -> edge-dns.local
    ESP_ERROR_CHECK(mdns_instance_name_set("edge DNS"));

    // The mdns component auto-advertises whatever A/AAAA addresses the STA
    // netif currently holds — no explicit address wiring needed here. IPv6
    // (AAAA) advertisement depends on wifi_connect.cpp having brought up a
    // link-local address on the netif; see its GOT_IP6 handling.
    mdns_txt_item_t txt[] = {{"path", "/"}};
    ESP_ERROR_CHECK(mdns_service_add(nullptr, "_http", "_tcp", 80, txt, 1));
}
