#include "wifi_connect.h"
#include "wifi_credentials.h"

#include <cstring>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "nvs_flash.h"

namespace {

constexpr const char *TAG = "wifi_connect";
constexpr int WIFI_CONNECTED_BIT = BIT0;

// How long wifi_connect_sta() waits for a first IP before giving up and
// falling back to the provisioning portal (see main.cpp's boot branch) — a
// router that's merely rebooting recovers on the *next* power cycle instead
// of this one, rather than the device hanging forever on a bad network.
constexpr uint32_t STA_CONNECT_TIMEOUT_MS = 30000;

EventGroupHandle_t s_wifi_event_group;
esp_netif_t *s_sta_netif;

// Set once the very first IP is obtained. Doesn't gate the disconnect-retry
// handler below (that stays unconditional, exactly as before this phase) —
// it only distinguishes "still trying the initial connect" from "recovering
// a connection that already worked once" in the log line, so a timeout
// during first boot doesn't read like an ordinary transient drop.
bool s_got_ip_once = false;

void event_handler(void *, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_got_ip_once) {
            ESP_LOGW(TAG, "disconnected, retrying...");
        } else {
            ESP_LOGW(TAG, "initial connect attempt failed, retrying...");
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        // Kicks off SLAAC for a link-local address on the STA netif — needed
        // so mDNS (Phase 4) has an IPv6 address to advertise as AAAA. Purely
        // additive: does not gate WIFI_CONNECTED_BIT, so IPv4 boot readiness
        // (below) is unaffected if this or IPv6 itself is unavailable.
        esp_netif_create_ip6_linklocal(s_sta_netif);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        auto *event = static_cast<ip_event_got_ip_t *>(event_data);
        ESP_LOGI(TAG, "connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_got_ip_once = true;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_GOT_IP6) {
        auto *event = static_cast<ip_event_got_ip6_t *>(event_data);
        ESP_LOGI(TAG, "IPv6 link-local: " IPV6STR, IPV62STR(event->ip6_info.ip));
    }
}

void init_nvs()
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

// netif/event-loop/esp_wifi_init bring-up shared by both the STA path
// (wifi_connect_sta(), below) and the AP provisioning path
// (wifi_provision_start(), in wifi_provision.cpp). Runs exactly once: it's
// only ever invoked from wifi_connect_sta(), which main.cpp calls exactly
// once at boot, before branching into either mode — see the boot flow in
// main.cpp.
void wifi_stack_init()
{
    init_nvs();

    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, nullptr, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, nullptr, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_GOT_IP6, &event_handler, nullptr, nullptr));
}

} // namespace

bool wifi_connect_sta()
{
    wifi_stack_init();

    // esp_wifi already persists wifi_config_t to its own NVS blob
    // (nvs.net80211, WIFI_STORAGE_FLASH default) — this get_config() call
    // *is* the "am I provisioned?" check, no separate namespace needed.
    wifi_config_t wifi_config = {};
    ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_STA, &wifi_config));

    if (wifi_config.sta.ssid[0] == '\0') {
        // First boot, nothing stored yet: seed from the gitignored
        // wifi_credentials.h convenience header — the same seed-then-persist
        // idiom as DnsRecordStore::load_from_nvs()'s first-boot branch, except
        // esp_wifi_set_config() below both seeds AND persists in one call, so
        // there's no separate save step to write.
        ESP_LOGI(TAG, "no stored Wi-Fi config, seeding from wifi_credentials.h");
        std::strncpy(reinterpret_cast<char *>(wifi_config.sta.ssid), WIFI_SSID,
                     sizeof(wifi_config.sta.ssid) - 1);
        std::strncpy(reinterpret_cast<char *>(wifi_config.sta.password), WIFI_PASSWORD,
                     sizeof(wifi_config.sta.password) - 1);
        wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    }

    if (wifi_config.sta.ssid[0] == '\0') {
        // Defensive only: wifi_credentials.h is a required gitignored header,
        // so an empty WIFI_SSID shouldn't happen — but starting STA on a blank
        // SSID would just burn the 30s wait below for a connection that was
        // never going to succeed.
        ESP_LOGE(TAG, "no stored config and no seed available, cannot start STA");
        return false;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Soft timeout, not portMAX_DELAY: a wrong/dead password must not hang
    // the device forever with no way in — see wifi_provision_start() for the
    // recovery path this falls back to.
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(STA_CONNECT_TIMEOUT_MS));
    if (!(bits & WIFI_CONNECTED_BIT)) {
        ESP_LOGW(TAG, "no IP within %u ms, falling back to provisioning",
                 static_cast<unsigned>(STA_CONNECT_TIMEOUT_MS));
        return false;
    }
    return true;
}
