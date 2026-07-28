#include "ota_updater.h"

#include <atomic>
#include <cstring>

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
// every few hours never approaches.
constexpr const char *GITHUB_RELEASES_URL =
    "https://api.github.com/repos/RndmCodeGuy20/mini_dns/releases/latest";
constexpr const char *USER_AGENT = "mini_dns-ota-updater";

// A slot must survive this long, with Wi-Fi already up (guaranteed by
// boot order — see ota_updater.h) and at least one DNS query actually
// answered, before it's trusted enough to cancel rollback. Long enough to
// rule out a crash-loop that only manifests once traffic arrives; short
// enough that a healthy device doesn't sit "pending verify" for long.
constexpr int64_t HEALTH_GATE_MIN_UPTIME_US = 30LL * 1000 * 1000;

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

// Written only by the background task; read via ota_updater_last_check().
// A single mutex-free struct copy is acceptable here for the same reason
// DnsMetricsSnapshot's per-field reads are (see dns_metrics.h) — this is a
// low-frequency status readout, not a hot path, and a torn read at worst
// shows a status one field out of date for one HTTP request.
OtaCheckStatus s_last_check;

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
        status.last_error = error;
        s_last_check = status;
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
        s_last_check = status;
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
        s_last_check = status;
        s_check_in_progress = false;
        esp_restart();
    }

    status.last_error = std::string("esp_https_ota failed: ") + esp_err_to_name(err);
    ESP_LOGE(TAG, "%s", status.last_error.c_str());
    s_last_check = status;
    s_check_in_progress = false;
}

void ota_task(void *)
{
    const int64_t boot_time_us = esp_timer_get_time();
    bool health_gate_passed = false;

    while (true) {
        if (!health_gate_passed) {
            int64_t uptime_us = esp_timer_get_time() - boot_time_us;
            if (uptime_us >= HEALTH_GATE_MIN_UPTIME_US && metrics().snapshot().queries >= 1) {
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
    OtaCheckStatus status = s_last_check;
    status.in_progress = s_check_in_progress;
    return status;
}

bool ota_updater_request_check()
{
    if (s_check_in_progress) {
        return false;
    }
    s_check_requested = true;
    return true;
}
