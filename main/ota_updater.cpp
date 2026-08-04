#include "ota_updater.h"

#include <atomic>
#include <cstring>
#include <mutex>

#include "cJSON.h"
#include "dns_metrics.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ota_version.h"

namespace {

constexpr const char *TAG = "ota_updater";

// GitHub requires a User-Agent on every API request or it 403s — the repo
// name doubles as a plausible one. No auth token: this hits the
// unauthenticated rate limit (60 req/hr per IP), which a device checking
// every OTA_CHECK_INTERVAL_US (6h) never approaches.
constexpr const char *GITHUB_RELEASES_URL =
    "https://api.github.com/repos/RndmCodeGuy20/mini_dns/releases/latest";
constexpr const char *USER_AGENT = "mini_dns-ota-updater";

// A slot must survive this long, with Wi-Fi already up (guaranteed by
// boot order — see ota_updater.h) and at least one DNS query actually
// answered, before it's trusted enough to cancel rollback. Long enough to
// rule out a crash-loop that only manifests once traffic arrives; short
// enough that a healthy device doesn't sit "pending verify" for long.
constexpr int64_t HEALTH_GATE_MIN_UPTIME_US = 30LL * 1000 * 1000;

// Absolute-time escape from the query-count requirement above: an idle
// device (no DNS traffic yet) that has nonetheless run this long without
// crashing is trusted even with zero queries — the alternative is an
// unrecoverable rollback of a genuinely healthy image just because nothing
// happened to query it yet.
constexpr int64_t HEALTH_GATE_MAX_UPTIME_US = 10LL * 60 * 1000 * 1000;

// How often the background task polls GitHub Releases on its own, absent
// a manual POST /api/ota/check — matches the rate-limit comment above.
constexpr int64_t OTA_CHECK_INTERVAL_US = 6LL * 3600 * 1000 * 1000;

// A failed check (rate-limited, DNS broken, no asset, etc.) is usually not
// transient on a device-restart timescale — without a cooldown, a naive
// dashboard retry loop can trigger a fresh check every ~5s forever. One
// fixed window, no backoff: this only needs to stop hammering, not be
// clever about it.
constexpr int64_t OTA_FAILURE_COOLDOWN_US = 30LL * 1000 * 1000;

// Response bodies from the GitHub API are capped here — generous headroom
// for a release with a handful of asset entries (tag_name appears near
// the top of the JSON regardless), not a real capacity need.
// ponytail: fixed cap, not a streaming JSON parser — raise this or switch
// to a streaming parse if a release ever grows enough assets to truncate
// the mini_dns.bin asset entry out of the buffer.
constexpr size_t MAX_RESPONSE_BYTES = 16384;

std::atomic<bool> s_valid_marked{false};
std::atomic<bool> s_check_requested{false};
std::atomic<bool> s_check_in_progress{false};
// esp_timer_get_time() of the last failed check cycle, 0 if none yet —
// gates ota_updater_request_check() during the cooldown window.
std::atomic<int64_t> s_last_failure_us{0};

// Written only by the background task, read via ota_updater_last_check()
// from the HTTP task. Guarded by s_last_check_mutex — unlike
// DnsMetricsSnapshot's plain fields, OtaCheckStatus holds std::string
// members, and a copy-assignment racing a concurrent read can free the
// source string's heap buffer mid-copy (use-after-free), not just return a
// stale value.
OtaCheckStatus s_last_check;
std::mutex s_last_check_mutex;

struct HttpResponseBuffer {
    std::string data;
};

esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        auto *buf = static_cast<HttpResponseBuffer *>(evt->user_data);
        if (buf->data.size() + evt->data_len <= MAX_RESPONSE_BYTES) {
            buf->data.append(static_cast<const char *>(evt->data),
                              static_cast<size_t>(evt->data_len));
        }
    }
    return ESP_OK;
}

// Fetches and parses GitHub's "latest release" JSON, extracting tag_name
// and the mini_dns.bin asset's download URL. Returns false with
// out_error set on any failure (network, HTTP status, JSON shape).
bool fetch_latest_release(std::string &out_tag, std::string &out_asset_url,
                           std::string &out_error)
{
    HttpResponseBuffer response;
    esp_http_client_config_t config = {};
    config.url = GITHUB_RELEASES_URL;
    config.event_handler = http_event_handler;
    config.user_data = &response;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.timeout_ms = 10000;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "User-Agent", USER_AGENT);
    esp_http_client_set_header(client, "Accept", "application/vnd.github+json");

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        out_error = std::string("http request failed: ") + esp_err_to_name(err);
        return false;
    }
    if (status != 200) {
        out_error = "GitHub API returned HTTP " + std::to_string(status);
        return false;
    }

    cJSON *root = cJSON_ParseWithLength(response.data.c_str(), response.data.size());
    if (root == nullptr) {
        out_error = "failed to parse release JSON";
        return false;
    }

    cJSON *tag_item = cJSON_GetObjectItemCaseSensitive(root, "tag_name");
    if (!cJSON_IsString(tag_item)) {
        cJSON_Delete(root);
        out_error = "release JSON missing tag_name";
        return false;
    }
    out_tag = tag_item->valuestring;

    cJSON *assets = cJSON_GetObjectItemCaseSensitive(root, "assets");
    cJSON *asset = nullptr;
    cJSON_ArrayForEach(asset, assets)
    {
        cJSON *name_item = cJSON_GetObjectItemCaseSensitive(asset, "name");
        if (cJSON_IsString(name_item) && std::strcmp(name_item->valuestring, "mini_dns.bin") == 0) {
            cJSON *url_item = cJSON_GetObjectItemCaseSensitive(asset, "browser_download_url");
            if (cJSON_IsString(url_item)) {
                out_asset_url = url_item->valuestring;
            }
            break;
        }
    }
    cJSON_Delete(root);

    if (out_asset_url.empty()) {
        out_error = "release has no mini_dns.bin asset";
        return false;
    }
    return true;
}

// Runs one full check-and-maybe-update cycle, updating s_last_check.
void run_check_cycle()
{
    s_check_in_progress = true;
    OtaCheckStatus status;
    status.checked = true;

    std::string tag, asset_url, error;
    if (!fetch_latest_release(tag, asset_url, error)) {
        // tag may already be valid even though this call failed overall —
        // e.g. tag_name parsed fine but no mini_dns.bin asset was found.
        // Surface it anyway so /api/ota shows the real latest tag alongside
        // the error instead of an empty string indistinguishable from
        // "never checked".
        status.latest_version = tag;
        status.last_error = error;
        {
            std::lock_guard<std::mutex> lock(s_last_check_mutex);
            s_last_check = status;
        }
        s_last_failure_us = esp_timer_get_time();
        s_check_in_progress = false;
        ESP_LOGW(TAG, "release check failed: %s", error.c_str());
        return;
    }

    status.latest_version = tag;
    const std::string current_version = esp_app_get_description()->version;
    status.update_available = ota_version_is_newer(current_version, tag);

    if (!status.update_available) {
        ESP_LOGI(TAG, "running %s, latest is %s — no update", current_version.c_str(),
                 tag.c_str());
        {
            std::lock_guard<std::mutex> lock(s_last_check_mutex);
            s_last_check = status;
        }
        s_check_in_progress = false;
        return;
    }

    ESP_LOGI(TAG, "update available: %s -> %s, downloading from %s", current_version.c_str(),
             tag.c_str(), asset_url.c_str());

    esp_http_client_config_t http_config = {};
    http_config.url = asset_url.c_str();
    http_config.crt_bundle_attach = esp_crt_bundle_attach;
    http_config.timeout_ms = 30000;
    http_config.keep_alive_enable = true;

    esp_https_ota_config_t ota_config = {};
    ota_config.http_config = &http_config;

    esp_err_t err = esp_https_ota(&ota_config);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "OTA succeeded, rebooting into %s", tag.c_str());
        {
            std::lock_guard<std::mutex> lock(s_last_check_mutex);
            s_last_check = status;
        }
        s_check_in_progress = false;
        esp_restart();
    }

    status.last_error = std::string("esp_https_ota failed: ") + esp_err_to_name(err);
    ESP_LOGE(TAG, "%s", status.last_error.c_str());
    {
        std::lock_guard<std::mutex> lock(s_last_check_mutex);
        s_last_check = status;
    }
    s_last_failure_us = esp_timer_get_time();
    s_check_in_progress = false;
}

void ota_task(void *)
{
    const int64_t boot_time_us = esp_timer_get_time();
    int64_t last_periodic_check_us = boot_time_us;
    bool health_gate_passed = false;

    while (true) {
        if (!health_gate_passed) {
            int64_t uptime_us = esp_timer_get_time() - boot_time_us;
            // Queries >= 1 is the normal path; the absolute-time fallback
            // (uptime past HEALTH_GATE_MAX_UPTIME_US) covers a healthy but
            // idle device that would otherwise never leave pending_verify
            // and get rolled back on its next reset despite being fine.
            if (uptime_us >= HEALTH_GATE_MIN_UPTIME_US &&
                (metrics().snapshot().queries >= 1 || uptime_us >= HEALTH_GATE_MAX_UPTIME_US)) {
                esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
                if (err == ESP_OK) {
                    s_valid_marked = true;
                    health_gate_passed = true;
                    ESP_LOGI(TAG, "health gate passed, cancelled rollback");
                } else {
                    ESP_LOGE(TAG, "esp_ota_mark_app_valid_cancel_rollback failed: %s",
                             esp_err_to_name(err));
                }
            }
        }

        if (s_check_requested.exchange(false)) {
            run_check_cycle();
        } else if (health_gate_passed &&
                   esp_timer_get_time() - last_periodic_check_us >= OTA_CHECK_INTERVAL_US) {
            last_periodic_check_us = esp_timer_get_time();
            run_check_cycle();
        }

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

} // namespace

void ota_updater_start()
{
    xTaskCreate(ota_task, "ota_updater", 8192, nullptr, tskIDLE_PRIORITY + 1, nullptr);
}

OtaHealthState ota_updater_health_state()
{
    return s_valid_marked ? OtaHealthState::kValid : OtaHealthState::kPendingVerify;
}

OtaCheckStatus ota_updater_last_check()
{
    // in_progress lives in its own atomic (s_check_in_progress), not inside
    // s_last_check, since it changes independently of a completed check's
    // result — stitched in here rather than stored redundantly in two places.
    OtaCheckStatus status;
    {
        std::lock_guard<std::mutex> lock(s_last_check_mutex);
        status = s_last_check;
    }
    status.in_progress = s_check_in_progress;
    return status;
}

bool ota_updater_request_check()
{
    if (s_check_in_progress) {
        return false;
    }
    if (!s_valid_marked) {
        // esp_ota_begin() rejects a new OTA attempt while the running image
        // is still pending_verify (ESP_ERR_OTA_ROLLBACK_INVALID_STATE) — fail
        // fast instead of letting a doomed attempt trip the failure cooldown.
        return false;
    }
    // s_last_failure_us == 0 means "never failed" — esp_timer_get_time()
    // itself returns values near 0 for roughly the first 30s after boot, so
    // without this guard the very first legitimate check request after
    // flashing/booting would be spuriously rejected as "within cooldown"
    // even though nothing has ever failed.
    if (s_last_failure_us != 0 &&
        esp_timer_get_time() - s_last_failure_us < OTA_FAILURE_COOLDOWN_US) {
        return false;
    }
    s_check_requested = true;
    return true;
}
