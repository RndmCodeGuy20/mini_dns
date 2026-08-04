#include "system_health.h"

#include "esp_core_dump.h"
#include "esp_log.h"

namespace {

constexpr const char *TAG = "system_health";

SystemHealth s_health = {ESP_RST_UNKNOWN, "unknown", false, 0};

const char *reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON:
        return "poweron";
    case ESP_RST_SW:
        return "sw";
    case ESP_RST_PANIC:
        return "panic";
    case ESP_RST_INT_WDT:
        return "int_wdt";
    case ESP_RST_TASK_WDT:
        return "task_wdt";
    case ESP_RST_WDT:
        return "wdt";
    case ESP_RST_DEEPSLEEP:
        return "deepsleep";
    case ESP_RST_BROWNOUT:
        return "brownout";
    case ESP_RST_SDIO:
        return "sdio";
    default:
        return "unknown";
    }
}

} // namespace

void system_health_report()
{
    s_health.reset_reason = esp_reset_reason();
    s_health.reset_reason_name = reset_reason_name(s_health.reset_reason);
    ESP_LOGI(TAG, "reset reason: %s", s_health.reset_reason_name);

    size_t addr = 0;
    size_t size = 0;
    if (esp_core_dump_image_get(&addr, &size) == ESP_OK) {
        s_health.coredump_present = true;
        s_health.coredump_size = static_cast<uint32_t>(size);
        ESP_LOGW(TAG, "coredump present: %u bytes, pull with `idf.py coredump-info`",
                 static_cast<unsigned>(size));
    }
}

SystemHealth system_health_snapshot()
{
    return s_health;
}
