#include "http_server.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include "cJSON.h"
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

} // namespace

void http_server_start()
{
    httpd_handle_t server = nullptr;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ROOT_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &RECORDS_URI));

    ESP_LOGI(TAG, "HTTP server listening on port %d", config.server_port);
}
