#include "http_server.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>

#include "admin_credentials.h"
#include "cJSON.h"
#include "dns_blocklist.h"
#include "dns_cache.h"
#include "dns_forwarder.h"
#include "dns_metrics.h"
#include "dns_record_store.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "mbedtls/base64.h"

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

std::string ipv6_to_string(const std::array<uint8_t, 16> &ip)
{
    char buf[46]; // longest possible IPv6 text form + NUL
    if (inet_ntop(AF_INET6, ip.data(), buf, sizeof(buf)) == nullptr) {
        return std::string();
    }
    return std::string(buf);
}

// Strict "A.B.C.D" parse: four decimal octets 0-255, nothing else on the
// string. Separate from (and stricter-checked-at-the-boundary than)
// DnsRecordStore's internal parser, since this one validates untrusted
// request bodies rather than re-parsing the store's own serialized format.
std::optional<std::array<uint8_t, 4>> parse_ipv4(const std::string &s)
{
    std::array<uint8_t, 4> ip{};
    size_t pos = 0;
    for (int octet = 0; octet < 4; ++octet) {
        if (pos >= s.size() || !std::isdigit(static_cast<unsigned char>(s[pos]))) {
            return std::nullopt;
        }
        int value = 0;
        int digits = 0;
        while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) {
            value = value * 10 + (s[pos] - '0');
            ++pos;
            ++digits;
            if (digits > 3 || value > 255) {
                return std::nullopt;
            }
        }
        ip[octet] = static_cast<uint8_t>(value);
        if (octet < 3) {
            if (pos >= s.size() || s[pos] != '.') {
                return std::nullopt;
            }
            ++pos;
        }
    }
    if (pos != s.size()) {
        return std::nullopt;
    }
    return ip;
}

std::optional<std::array<uint8_t, 16>> parse_ipv6(const std::string &s)
{
    std::array<uint8_t, 16> ip{};
    if (inet_pton(AF_INET6, s.c_str(), ip.data()) != 1) {
        return std::nullopt;
    }
    return ip;
}

// Syntax check only (RFC 1035 label rules) — deliberately not aware of the
// ".loc"/".local" TLD gotchas documented in ARCHITECTURE.md; any hostname
// worth these rules is accepted, matching a client's own liberty to pick a
// TLD.
bool valid_hostname(const std::string &host)
{
    if (host.empty() || host.size() > 253) {
        return false;
    }
    size_t label_start = 0;
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i < host.size() && host[i] != '.') {
            continue;
        }
        size_t label_len = i - label_start;
        if (label_len == 0 || label_len > 63) {
            return false;
        }
        if (host[label_start] == '-' || host[i - 1] == '-') {
            return false;
        }
        for (size_t j = label_start; j < i; ++j) {
            if (!std::isalnum(static_cast<unsigned char>(host[j])) && host[j] != '-') {
                return false;
            }
        }
        label_start = i + 1;
    }
    return true;
}

// Reflects the request's Origin back rather than "*": the mutating routes
// use Basic-auth credentials, and browsers reject Access-Control-Allow-
// Origin: * combined with credentialed requests. Effectively an open CORS
// policy — protection comes from check_auth(), not from origin filtering.
// Call on every /api/records handler a browser (not just curl/dig) will hit.
//
// `origin_buf` is an out-parameter owned by the CALLER, not this function:
// httpd_resp_set_hdr() only stores the pointer it's given, not a copy (see
// its doc comment — "lifetime of the field value strings [must be] valid
// till send function is called"), so the buffer must outlive this call and
// stay alive until the handler's own httpd_resp_send(). A local here would
// go out of scope the moment this function returns, leaving httpd holding a
// dangling pointer by the time the response is actually serialized.
void add_cors_headers(httpd_req_t *req, char *origin_buf, size_t origin_buf_size)
{
    if (httpd_req_get_hdr_value_str(req, "Origin", origin_buf, origin_buf_size) == ESP_OK) {
        httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", origin_buf);
        httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
    }
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Authorization,Content-Type");
}

// HTTP Basic auth, checked only on the mutating /api/records routes — every
// GET (dashboard, /api/records, /api/blocklist, /metrics) stays open so
// Prometheus can keep scraping unauthenticated (see Phase 3). Credentials
// live in admin_credentials.h, gitignored like wifi_credentials.h. Sends 401
// + WWW-Authenticate itself on failure; caller just returns on `false`.
bool check_auth(httpd_req_t *req)
{
    char header[128];
    if (httpd_req_get_hdr_value_str(req, "Authorization", header, sizeof(header)) != ESP_OK) {
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"mini_dns\"");
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_send(req, nullptr, 0);
        return false;
    }

    constexpr const char *PREFIX = "Basic ";
    constexpr size_t PREFIX_LEN = 6;
    std::string token(header);
    bool ok = false;
    if (token.rfind(PREFIX, 0) == 0) {
        std::string encoded = token.substr(PREFIX_LEN);
        unsigned char decoded[128];
        size_t decoded_len = 0;
        if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_len,
                                   reinterpret_cast<const unsigned char *>(encoded.c_str()),
                                   encoded.size()) == 0) {
            decoded[decoded_len] = '\0';
            std::string creds(reinterpret_cast<char *>(decoded), decoded_len);
            std::string expected = std::string(ADMIN_USER) + ':' + ADMIN_PASS;
            ok = (creds == expected);
        }
    }

    if (!ok) {
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"mini_dns\"");
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_send(req, nullptr, 0);
        return false;
    }
    return true;
}

// Reads the request body into a cJSON object. Rejects bodies over 1KB (a
// record entry is a handful of bytes; this is generous headroom, not a
// real capacity need) and returns nullptr on any read/parse failure —
// callers respond 400.
cJSON *read_json_body(httpd_req_t *req)
{
    if (req->content_len == 0 || req->content_len > 1024) {
        return nullptr;
    }
    std::string body(req->content_len, '\0');
    size_t received = 0;
    while (received < req->content_len) {
        int ret = httpd_req_recv(req, body.data() + received, req->content_len - received);
        if (ret <= 0) {
            return nullptr;
        }
        received += static_cast<size_t>(ret);
    }
    return cJSON_ParseWithLength(body.c_str(), body.size());
}

// Pulls {"host": "...", "ip"?: "...", "ipv6"?: "..."} out of a parsed body,
// validating each field present. `require_address` is false for DELETE,
// which only needs the host. For create/update, at least one of ip/ipv6
// must be present and valid (dual-stack — Phase 6): a record with neither
// address is meaningless, so that's rejected here rather than deferred to
// the store. Sends 400 itself on any validation failure so callers just
// return on `false`.
bool parse_record_request(httpd_req_t *req, cJSON *body, bool require_address, std::string &host,
                           std::optional<std::array<uint8_t, 4>> &ipv4,
                           std::optional<std::array<uint8_t, 16>> &ipv6)
{
    cJSON *host_item = cJSON_GetObjectItemCaseSensitive(body, "host");
    if (!cJSON_IsString(host_item) || !valid_hostname(host_item->valuestring)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid or missing \"host\"");
        return false;
    }
    host = host_item->valuestring;

    if (!require_address) {
        return true;
    }

    ipv4 = std::nullopt;
    ipv6 = std::nullopt;

    cJSON *ip_item = cJSON_GetObjectItemCaseSensitive(body, "ip");
    if (ip_item != nullptr) {
        if (!cJSON_IsString(ip_item)) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid \"ip\"");
            return false;
        }
        auto parsed = parse_ipv4(ip_item->valuestring);
        if (!parsed) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid \"ip\"");
            return false;
        }
        ipv4 = *parsed;
    }

    cJSON *ipv6_item = cJSON_GetObjectItemCaseSensitive(body, "ipv6");
    if (ipv6_item != nullptr) {
        if (!cJSON_IsString(ipv6_item)) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid \"ipv6\"");
            return false;
        }
        auto parsed = parse_ipv6(ipv6_item->valuestring);
        if (!parsed) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid \"ipv6\"");
            return false;
        }
        ipv6 = *parsed;
    }

    if (!ipv4 && !ipv6) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "at least one of \"ip\"/\"ipv6\" required");
        return false;
    }
    return true;
}

esp_err_t records_get_handler(httpd_req_t *req)
{
    char origin[128];
    add_cors_headers(req, origin, sizeof(origin));
    cJSON *root = cJSON_CreateArray();
    if (root == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate JSON array");
        return httpd_resp_send_500(req);
    }

    for (const auto &record : record_store().snapshot()) {
        cJSON *entry = cJSON_CreateObject();
        if (entry == nullptr) {
            ESP_LOGE(TAG, "Failed to allocate JSON object");
            cJSON_Delete(root);
            return httpd_resp_send_500(req);
        }
        cJSON_AddStringToObject(entry, "host", record.hostname.c_str());
        if (record.ipv4) {
            cJSON_AddStringToObject(entry, "ip", ip_to_string(*record.ipv4).c_str());
        }
        if (record.ipv6) {
            cJSON_AddStringToObject(entry, "ipv6", ipv6_to_string(*record.ipv6).c_str());
        }
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

constexpr httpd_uri_t RECORDS_GET_URI = {
    .uri = "/api/records",
    .method = HTTP_GET,
    .handler = records_get_handler,
    .user_ctx = nullptr,
};

esp_err_t records_options_handler(httpd_req_t *req)
{
    char origin[128];
    add_cors_headers(req, origin, sizeof(origin));
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, nullptr, 0);
}

constexpr httpd_uri_t RECORDS_OPTIONS_URI = {
    .uri = "/api/records",
    .method = HTTP_OPTIONS,
    .handler = records_options_handler,
    .user_ctx = nullptr,
};

esp_err_t records_post_handler(httpd_req_t *req)
{
    char origin[128];
    add_cors_headers(req, origin, sizeof(origin));
    if (!check_auth(req)) {
        return ESP_OK;
    }
    cJSON *body = read_json_body(req);
    if (body == nullptr) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON body");
    }
    std::string host;
    std::optional<std::array<uint8_t, 4>> ipv4;
    std::optional<std::array<uint8_t, 16>> ipv6;
    if (!parse_record_request(req, body, /*require_address=*/true, host, ipv4, ipv6)) {
        cJSON_Delete(body);
        return ESP_OK; // parse_record_request already sent the error response
    }
    cJSON_Delete(body);

    switch (record_store().create(host, ipv4, ipv6)) {
    case DnsRecordStoreResult::kOk:
        httpd_resp_set_status(req, "201 Created");
        return httpd_resp_send(req, nullptr, 0);
    case DnsRecordStoreResult::kAlreadyExists:
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "host already exists");
    case DnsRecordStoreResult::kNoAddress:
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "at least one of \"ip\"/\"ipv6\" required");
    case DnsRecordStoreResult::kFull:
    default:
        httpd_resp_set_status(req, "507 Insufficient Storage");
        return httpd_resp_send(req, nullptr, 0);
    }
}

constexpr httpd_uri_t RECORDS_POST_URI = {
    .uri = "/api/records",
    .method = HTTP_POST,
    .handler = records_post_handler,
    .user_ctx = nullptr,
};

esp_err_t records_put_handler(httpd_req_t *req)
{
    char origin[128];
    add_cors_headers(req, origin, sizeof(origin));
    if (!check_auth(req)) {
        return ESP_OK;
    }
    cJSON *body = read_json_body(req);
    if (body == nullptr) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON body");
    }
    std::string host;
    std::optional<std::array<uint8_t, 4>> ipv4;
    std::optional<std::array<uint8_t, 16>> ipv6;
    if (!parse_record_request(req, body, /*require_address=*/true, host, ipv4, ipv6)) {
        cJSON_Delete(body);
        return ESP_OK;
    }
    cJSON_Delete(body);

    switch (record_store().update(host, ipv4, ipv6)) {
    case DnsRecordStoreResult::kOk:
        return httpd_resp_send(req, nullptr, 0);
    case DnsRecordStoreResult::kNoAddress:
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "at least one of \"ip\"/\"ipv6\" required");
    case DnsRecordStoreResult::kNotFound:
    default:
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "host not found");
    }
}

constexpr httpd_uri_t RECORDS_PUT_URI = {
    .uri = "/api/records",
    .method = HTTP_PUT,
    .handler = records_put_handler,
    .user_ctx = nullptr,
};

esp_err_t records_delete_handler(httpd_req_t *req)
{
    char origin[128];
    add_cors_headers(req, origin, sizeof(origin));
    if (!check_auth(req)) {
        return ESP_OK;
    }
    cJSON *body = read_json_body(req);
    if (body == nullptr) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON body");
    }
    std::string host;
    std::optional<std::array<uint8_t, 4>> ipv4;   // unused, DELETE only needs host
    std::optional<std::array<uint8_t, 16>> ipv6; // unused, DELETE only needs host
    if (!parse_record_request(req, body, /*require_address=*/false, host, ipv4, ipv6)) {
        cJSON_Delete(body);
        return ESP_OK;
    }
    cJSON_Delete(body);

    switch (record_store().remove(host)) {
    case DnsRecordStoreResult::kOk:
        return httpd_resp_send(req, nullptr, 0);
    case DnsRecordStoreResult::kNotFound:
    default:
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "host not found");
    }
}

constexpr httpd_uri_t RECORDS_DELETE_URI = {
    .uri = "/api/records",
    .method = HTTP_DELETE,
    .handler = records_delete_handler,
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
                          "In-flight queries that timed out waiting on upstream (after "
                          "exhausting the secondary retry)",
                          snap.upstream_timeouts);
    append_simple_metric(out, "dns_upstream_retries_total", "counter",
                          "In-flight queries retried against the secondary upstream after the "
                          "primary timed out",
                          snap.upstream_retries);
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
    // Default (8) was an exact fit for the prior 4 GET-only routes; Phase 5
    // adds POST/PUT/DELETE/OPTIONS on /api/records (8 handlers total), so
    // bump with real headroom rather than the exact new count — the same
    // "leave headroom, don't just +1" lesson as the Phase 1 socket-budget
    // trap (see ARCHITECTURE.md).
    config.max_uri_handlers = 12;

    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ROOT_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &RECORDS_GET_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &RECORDS_POST_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &RECORDS_PUT_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &RECORDS_DELETE_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &RECORDS_OPTIONS_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &BLOCKLIST_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &METRICS_URI));

    ESP_LOGI(TAG, "HTTP server listening on port %d", config.server_port);
}
