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
    // The tag parsed during the most recent check cycle, if that cycle got
    // that far — run_check_cycle() starts from a fresh, empty OtaCheckStatus
    // every cycle, so this is NOT "the most recent tag ever parsed": a
    // network/HTTP/JSON-shape failure that happens before the tag_name parse
    // step clears it back to empty, even if a prior cycle had populated it.
    // May be populated even when last_error is non-empty — e.g. the release
    // parsed fine but had no mini_dns.bin asset.
    std::string latest_version;
    std::string last_error;       // empty on success
};
OtaCheckStatus ota_updater_last_check();

// Auth-gated HTTP trigger (POST /api/ota/check in http_server.cpp): asks
// the background task to run a check-and-update cycle now rather than
// waiting for its periodic interval. Returns false (no-op, caller should
// report 409 Conflict) if a cycle is already in progress, if the running
// image hasn't passed its health gate yet (esp_ota_begin() rejects OTA
// while pending_verify), or if a prior cycle failed within the cooldown
// window.
bool ota_updater_request_check();
