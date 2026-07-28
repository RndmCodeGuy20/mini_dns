#pragma once

#include <string>

// Background OTA task (Phase 7a): gates marking the running app image
// valid behind a real health check instead of doing it unconditionally at
// boot, and checks GitHub Releases for a newer tagged version — see
// ARCHITECTURE.md's OTA section for the rollback rationale.
//
// Call once from app_main(), after dns_server_start() (the health gate
// reads metrics().snapshot().queries, which is only meaningful once the
// DNS task is running) and http_server_start() (so /api/ota can report
// status immediately).
void ota_updater_start();

enum class OtaHealthState {
    kPendingVerify, // running image not yet marked valid; a reset now rolls back
    kValid,         // marked valid via esp_ota_mark_app_valid_cancel_rollback()
};
OtaHealthState ota_updater_health_state();

struct OtaCheckStatus {
    bool checked = false;         // false until the first check cycle has run
    bool in_progress = false;     // a check-and-update cycle is currently running
    bool update_available = false;
    std::string latest_version;   // empty until checked = true
    std::string last_error;       // empty on success
};
OtaCheckStatus ota_updater_last_check();

// Auth-gated HTTP trigger (POST /api/ota/check in http_server.cpp): asks
// the background task to run a check-and-update cycle now rather than
// waiting for its periodic interval. Returns false (no-op) if a cycle is
// already in progress — the caller should report 409 Conflict.
bool ota_updater_request_check();
