#include "dns_server.h"
#include "esp_log.h"
#include "esp_psram.h"
#include "http_server.h"
#include "mdns_responder.h"
#include "ota_updater.h"
#include "system_health.h"
#include "wifi_connect.h"
#include "wifi_provision.h"

namespace {
constexpr const char *TAG = "main";

// Logs whether PSRAM initialized and at what size, so a mismatched
// quad-vs-octal sdkconfig assumption (see sdkconfig.defaults) shows up
// immediately in the boot log rather than as a mysterious cache-capacity
// shortfall later.
void log_psram_status()
{
    if (esp_psram_is_initialized()) {
        ESP_LOGI(TAG, "PSRAM initialized: %u bytes", static_cast<unsigned>(esp_psram_get_size()));
    } else {
        ESP_LOGW(TAG, "PSRAM not initialized — running SRAM-only, cache capacity reduced");
    }
}
} // namespace

extern "C" void app_main(void)
{
    system_health_report();
    log_psram_status();
    if (wifi_connect_sta()) {
        dns_server_start();
        http_server_start();
        mdns_responder_start();
        ota_updater_start();
        factory_reset_watch_start();
    } else {
        wifi_provision_start();
    }
}
