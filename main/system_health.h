#pragma once

#include "esp_system.h"
#include <cstdint>

// Cached rather than re-read on every /metrics scrape: reset reason and
// coredump presence can't change between boots, and esp_core_dump_image_get()
// is a flash read.
struct SystemHealth {
    esp_reset_reason_t reset_reason;
    const char *reset_reason_name;
    bool coredump_present;
    uint32_t coredump_size;
};

// Call first thing in app_main(), before anything else that might itself
// crash, so the resulting reset reason/coredump state reflects the
// *previous* boot, not this one.
void system_health_report();

// Cached result of system_health_report(); call after it, not before.
SystemHealth system_health_snapshot();
