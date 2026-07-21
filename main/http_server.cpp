#include "http_server.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include "cJSON.h"
#include "dns_blocklist.h"
#include "dns_cache.h"
#include "dns_forwarder.h"
#include "dns_metrics.h"
#include "dns_records.h"
#include "esp_http_server.h"
#include "esp_log.h"

namespace {

constexpr const char *TAG = "http_server";

constexpr const char *ROOT_PAGE_BODY = R"HTML(<!DOCTYPE html>
<html>
<head><title>DNS Appliance</title></head>
<body>
  <h1>DNS Appliance POC</h1>
  <table>
    <thead><tr><th>Host</th><th>IP</th></tr></thead>
    <tbody id="records"></tbody>
  </table>
  <script>
    fetch('/api/records')
      .then(res => res.json())
      .then(records => {
        const tbody = document.getElementById('records');
        records.forEach(record => {
          const row = document.createElement('tr');
          const hostCell = document.createElement('td');
          hostCell.textContent = record.host;
          const ipCell = document.createElement('td');
          ipCell.textContent = record.ip;
          row.append(hostCell, ipCell);
          tbody.appendChild(row);
        });
      })
      .catch(err => {
        document.body.append(`Failed to load records: ${err}`);
      });
  </script>
</body>
</html>
)HTML";

esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, ROOT_PAGE_BODY, HTTPD_RESP_USE_STRLEN);
}

constexpr httpd_uri_t ROOT_URI = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler,
    .user_ctx = nullptr,
};

std::string ip_to_string(const std::array<uint8_t, 4> &ip)
{
    char buf[16]; // "255.255.255.255" + NUL
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return std::string(buf);
}

esp_err_t records_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateArray();
    if (root == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate JSON array");
        return httpd_resp_send_500(req);
    }

    for (const auto &record : DNS_RECORDS) {
        cJSON *entry = cJSON_CreateObject();
        if (entry == nullptr) {
            ESP_LOGE(TAG, "Failed to allocate JSON object");
            cJSON_Delete(root);
            return httpd_resp_send_500(req);
        }
        cJSON_AddStringToObject(entry, "host", record.hostname);
        cJSON_AddStringToObject(entry, "ip", ip_to_string(record.ip).c_str());
        cJSON_AddItemToArray(root, entry);
    }

    char *json_str = cJSON_PrintUnformatted(root);
    if (json_str == nullptr) {
        ESP_LOGE(TAG, "Failed to serialize JSON");
        cJSON_Delete(root);
        return httpd_resp_send_500(req);
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    cJSON_free(json_str);
    cJSON_Delete(root);
    return ret;
}

constexpr httpd_uri_t RECORDS_URI = {
    .uri = "/api/records",
    .method = HTTP_GET,
    .handler = records_get_handler,
    .user_ctx = nullptr,
};

esp_err_t blocklist_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate JSON object");
        return httpd_resp_send_500(req);
    }

    const DnsBlocklist &bl = blocklist();
    cJSON_AddNumberToObject(root, "count", static_cast<double>(bl.size()));
    cJSON_AddNumberToObject(root, "blocked_total", static_cast<double>(bl.blocks_total()));

    cJSON *domains = cJSON_CreateArray();
    if (domains == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate JSON array");
        cJSON_Delete(root);
        return httpd_resp_send_500(req);
    }
    for (const auto &domain : bl.domains()) {
        cJSON_AddItemToArray(domains, cJSON_CreateString(domain.c_str()));
    }
    cJSON_AddItemToObject(root, "domains", domains);

    char *json_str = cJSON_PrintUnformatted(root);
    if (json_str == nullptr) {
        ESP_LOGE(TAG, "Failed to serialize JSON");
        cJSON_Delete(root);
        return httpd_resp_send_500(req);
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    cJSON_free(json_str);
    cJSON_Delete(root);
    return ret;
}

constexpr httpd_uri_t BLOCKLIST_URI = {
    .uri = "/api/blocklist",
    .method = HTTP_GET,
    .handler = blocklist_get_handler,
    .user_ctx = nullptr,
};

// Appends one counter/gauge family: HELP + TYPE header lines, then a
// single sample line. Prometheus text exposition format (version 0.0.4).
void append_simple_metric(std::string &out, const char *name, const char *type,
                           const char *help, double value)
{
    out += "# HELP ";
    out += name;
    out += ' ';
    out += help;
    out += "\n# TYPE ";
    out += name;
    out += ' ';
    out += type;
    out += '\n';
    out += name;
    out += ' ';
    char value_buf[32];
    std::snprintf(value_buf, sizeof(value_buf), "%.17g", value);
    out += value_buf;
    out += '\n';
}

// Appends the upstream latency histogram: cumulative bucket counts (as
// Prometheus histograms require — each bucket includes everything at or
// below its own "le" bound, up to +Inf), plus _sum and _count.
void append_latency_histogram(std::string &out, const DnsMetricsSnapshot &snap)
{
    constexpr const char *NAME = "dns_upstream_latency_ms";
    out += "# HELP ";
    out += NAME;
    out += " Upstream resolver round-trip time in milliseconds\n# TYPE ";
    out += NAME;
    out += " histogram\n";

    uint32_t cumulative = 0;
    char line[96];
    for (size_t i = 0; i < DNS_METRICS_LATENCY_BUCKETS_MS.size(); ++i) {
        cumulative += snap.latency_buckets[i];
        std::snprintf(line, sizeof(line), "%s_bucket{le=\"%u\"} %u\n", NAME,
                      static_cast<unsigned>(DNS_METRICS_LATENCY_BUCKETS_MS[i]),
                      static_cast<unsigned>(cumulative));
        out += line;
    }
    cumulative += snap.latency_buckets[DNS_METRICS_LATENCY_BUCKETS_MS.size()];
    std::snprintf(line, sizeof(line), "%s_bucket{le=\"+Inf\"} %u\n", NAME,
                  static_cast<unsigned>(cumulative));
    out += line;
    std::snprintf(line, sizeof(line), "%s_sum %llu\n", NAME,
                  static_cast<unsigned long long>(snap.latency_sum_ms));
    out += line;
    std::snprintf(line, sizeof(line), "%s_count %u\n", NAME,
                  static_cast<unsigned>(snap.latency_count));
    out += line;
}

esp_err_t metrics_get_handler(httpd_req_t *req)
{
    DnsMetricsSnapshot snap = metrics().snapshot();
    const DnsBlocklist &bl = blocklist();

    std::string out;
    out.reserve(2048);

    append_simple_metric(out, "dns_queries_total", "counter",
                          "Total DNS queries received", snap.queries);
    append_simple_metric(out, "dns_local_hits_total", "counter",
                          "Queries answered from the local static table", snap.local_hits);
    append_simple_metric(out, "dns_cache_hits_total", "counter",
                          "Queries answered from the TTL cache", snap.cache_hits);
    append_simple_metric(out, "dns_cache_misses_total", "counter",
                          "Queries not found in the TTL cache", snap.cache_misses);
    append_simple_metric(out, "dns_forwarded_total", "counter",
                          "Queries forwarded to the upstream resolver", snap.forwarded);
    append_simple_metric(out, "dns_upstream_replies_total", "counter",
                          "Replies received from the upstream resolver", snap.upstream_replies);
    append_simple_metric(out, "dns_upstream_timeouts_total", "counter",
                          "In-flight queries that timed out waiting on upstream",
                          snap.upstream_timeouts);
    append_simple_metric(out, "dns_servfail_total", "counter",
                          "SERVFAIL responses sent to clients", snap.servfail);
    append_simple_metric(out, "dns_blocked_total", "counter",
                          "Queries sinkholed by the ad-block list", bl.blocks_total());
    append_latency_histogram(out, snap);
    append_simple_metric(out, "dns_cache_entries", "gauge",
                          "Current occupied TTL cache slots", snap.cache_entries);
    append_simple_metric(out, "dns_cache_capacity", "gauge", "TTL cache capacity",
                          DNS_CACHE_CAPACITY);
    append_simple_metric(out, "dns_inflight_queries", "gauge",
                          "Current in-flight upstream queries", snap.inflight);
    append_simple_metric(out, "dns_inflight_capacity", "gauge", "In-flight query table capacity",
                          DNS_FORWARDER_MAX_IN_FLIGHT);
    append_simple_metric(out, "dns_blocklist_domains", "gauge",
                          "Domains currently loaded in the ad-block list", bl.size());

    httpd_resp_set_type(req, "text/plain; version=0.0.4");
    return httpd_resp_send(req, out.c_str(), static_cast<ssize_t>(out.size()));
}

constexpr httpd_uri_t METRICS_URI = {
    .uri = "/metrics",
    .method = HTTP_GET,
    .handler = metrics_get_handler,
    .user_ctx = nullptr,
};

} // namespace

void http_server_start()
{
    httpd_handle_t server = nullptr;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ROOT_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &RECORDS_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &BLOCKLIST_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &METRICS_URI));

    ESP_LOGI(TAG, "HTTP server listening on port %d", config.server_port);
}
