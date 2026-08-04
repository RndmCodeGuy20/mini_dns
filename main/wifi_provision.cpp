#include "wifi_provision.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "cJSON.h"
#include "dns_wire.h"
#include "driver/gpio.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_wifi_default.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "provision_validate.h"

namespace {

constexpr const char *TAG = "wifi_provision";

// Open, no password: this AP only exists because there's no other way in,
// so physical proximity (being close enough to see and join it) is the
// access control — gating it behind a secret would defeat its own purpose.
constexpr const char *AP_SSID = "edge-dns-setup";

constexpr size_t RX_BUFFER_SIZE = 512;
constexpr size_t TX_BUFFER_SIZE = 512;

// The lwip DHCP server's "offer DNS server" bit (OFFER_DNS in
// dhcpserver.h). Defined locally rather than pulling in that header, same
// as the esp-idf softap_sta example — it's a single stable byte value, not
// worth a component dependency.
constexpr uint8_t DHCPS_OFFER_DNS = 0x02;

// Set once in wifi_provision_start(), before the captive DNS task is
// created; read-only from then on, so no locking needed across the two
// tasks.
std::array<uint8_t, 4> s_ap_ip;

constexpr const char *PORTAL_PAGE_BODY = R"HTML(<!DOCTYPE html>
<html>
<head><title>edge-dns setup</title></head>
<body>
  <h1>Wi-Fi setup</h1>
  <p>Pick a network (or type one manually) and enter its password.</p>
  <form id="form">
    <select id="ssid-select"><option value="">-- scanning... --</option></select><br>
    <input id="ssid-manual" type="text" placeholder="or type SSID manually"><br>
    <input id="password" type="password" placeholder="password (blank for open network)"><br>
    <button type="submit">Connect</button>
  </form>
  <p id="status"></p>
  <script>
    fetch('/scan')
      .then(res => res.json())
      .then(networks => {
        const select = document.getElementById('ssid-select');
        select.innerHTML = '';
        const blank = document.createElement('option');
        blank.value = '';
        blank.textContent = '-- select --';
        select.appendChild(blank);
        networks.forEach(net => {
          const opt = document.createElement('option');
          opt.value = net.ssid;
          // textContent, not innerHTML: SSIDs are attacker-controllable
          // strings received over the air, this is what keeps them from
          // being interpreted as markup.
          opt.textContent = `${net.ssid} (${net.auth}, ${net.rssi} dBm)`;
          select.appendChild(opt);
        });
      })
      .catch(err => {
        document.getElementById('status').textContent = `scan failed: ${err}`;
      });

    document.getElementById('form').addEventListener('submit', ev => {
      ev.preventDefault();
      const ssid = document.getElementById('ssid-manual').value
        || document.getElementById('ssid-select').value;
      const password = document.getElementById('password').value;
      document.getElementById('status').textContent = 'connecting...';
      fetch('/provision', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ssid, password}),
      })
        .then(res => {
          if (res.ok) {
            document.getElementById('status').textContent =
              'saved — device is rebooting onto that network.';
          } else {
            return res.text().then(msg => { throw new Error(msg); });
          }
        })
        .catch(err => {
          document.getElementById('status').textContent = `failed: ${err}`;
        });
    });
  </script>
</body>
</html>
)HTML";

const char *auth_mode_to_string(wifi_auth_mode_t mode)
{
    switch (mode) {
    case WIFI_AUTH_OPEN:
        return "open";
    case WIFI_AUTH_WEP:
        return "wep";
    case WIFI_AUTH_WPA_PSK:
        return "wpa";
    case WIFI_AUTH_WPA2_PSK:
        return "wpa2";
    case WIFI_AUTH_WPA_WPA2_PSK:
        return "wpa/wpa2";
    case WIFI_AUTH_WPA3_PSK:
        return "wpa3";
    case WIFI_AUTH_WPA2_WPA3_PSK:
        return "wpa2/wpa3";
    default:
        return "other";
    }
}

// Blocking scan (esp_wifi_scan_start's second arg) — briefly disrupts the
// AP, which is fine for a form the user only submits once, but is exactly
// why the portal only scans on page load rather than polling.
esp_err_t scan_get_handler(httpd_req_t *req)
{
    esp_err_t err = esp_wifi_scan_start(nullptr, true);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_scan_start failed: %s", esp_err_to_name(err));
        return httpd_resp_send_500(req);
    }

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);
    // Generous headroom for a bench network, not a real capacity need — a
    // dense-apartment-building scan would just get truncated here.
    constexpr uint16_t MAX_SCAN_RESULTS = 32;
    ap_count = std::min(ap_count, MAX_SCAN_RESULTS);

    std::vector<wifi_ap_record_t> records(ap_count);
    if (ap_count > 0) {
        err = esp_wifi_scan_get_ap_records(&ap_count, records.data());
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "esp_wifi_scan_get_ap_records failed: %s", esp_err_to_name(err));
            return httpd_resp_send_500(req);
        }
        records.resize(ap_count);
    }

    // Dedup by SSID keeping the strongest RSSI seen — the same network is
    // routinely heard on multiple channels/BSSIDs, and the picker only
    // needs one entry per name.
    std::vector<wifi_ap_record_t> deduped;
    for (const auto &rec : records) {
        if (rec.ssid[0] == '\0') {
            continue; // hidden network: nothing to show, and not matchable by name later
        }
        auto it = std::find_if(deduped.begin(), deduped.end(), [&](const wifi_ap_record_t &d) {
            return std::strncmp(reinterpret_cast<const char *>(d.ssid),
                                 reinterpret_cast<const char *>(rec.ssid), sizeof(d.ssid)) == 0;
        });
        if (it == deduped.end()) {
            deduped.push_back(rec);
        } else if (rec.rssi > it->rssi) {
            *it = rec;
        }
    }
    std::sort(deduped.begin(), deduped.end(),
              [](const wifi_ap_record_t &a, const wifi_ap_record_t &b) { return a.rssi > b.rssi; });

    cJSON *root = cJSON_CreateArray();
    if (root == nullptr) {
        ESP_LOGE(TAG, "failed to allocate JSON array");
        return httpd_resp_send_500(req);
    }
    for (const auto &rec : deduped) {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "ssid", reinterpret_cast<const char *>(rec.ssid));
        cJSON_AddNumberToObject(entry, "rssi", rec.rssi);
        cJSON_AddStringToObject(entry, "auth", auth_mode_to_string(rec.authmode));
        cJSON_AddItemToArray(root, entry);
    }

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json_str == nullptr) {
        ESP_LOGE(TAG, "failed to serialize scan JSON");
        return httpd_resp_send_500(req);
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    cJSON_free(json_str);
    return ret;
}

constexpr httpd_uri_t SCAN_URI = {
    .uri = "/scan",
    .method = HTTP_GET,
    .handler = scan_get_handler,
    .user_ctx = nullptr,
};

// One-shot task: esp_restart() called directly from the handler would cut
// the httpd response off mid-flush, so the reboot happens here instead,
// after a short delay long enough for the response to actually reach the
// browser.
void provision_reboot_task(void *)
{
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
}

esp_err_t provision_post_handler(httpd_req_t *req)
{
    // A {"ssid","password"} body is a handful of bytes; this is headroom,
    // not a real capacity need — same reasoning as http_server.cpp's
    // read_json_body cap.
    if (req->content_len == 0 || req->content_len > 512) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
    }
    std::string body(req->content_len, '\0');
    size_t received = 0;
    while (received < req->content_len) {
        int ret = httpd_req_recv(req, body.data() + received, req->content_len - received);
        if (ret <= 0) {
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "failed to read body");
        }
        received += static_cast<size_t>(ret);
    }

    cJSON *root = cJSON_ParseWithLength(body.c_str(), body.size());
    if (root == nullptr) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON body");
    }
    cJSON *ssid_item = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    cJSON *password_item = cJSON_GetObjectItemCaseSensitive(root, "password");
    if (!cJSON_IsString(ssid_item)) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing \"ssid\"");
    }
    std::string ssid = ssid_item->valuestring;
    std::string password = cJSON_IsString(password_item) ? password_item->valuestring : "";
    cJSON_Delete(root);

    switch (provision_validate(ssid, password)) {
    case ProvisionValidation::kSsidEmpty:
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ssid must not be empty");
    case ProvisionValidation::kSsidTooLong:
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ssid too long (max 32 bytes)");
    case ProvisionValidation::kPasswordTooShort:
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "password too short (min 8 bytes)");
    case ProvisionValidation::kPasswordTooLong:
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "password too long (max 63 bytes)");
    case ProvisionValidation::kOk:
        break;
    default:
        // Belt-and-suspenders, same as the DnsRecordStoreResult switches in
        // http_server.cpp: a future ProvisionValidation value added and
        // missed here must not silently fall through to kOk's break and
        // write an unvalidated config.
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid ssid/password");
    }

    wifi_config_t sta_config = {};
    std::strncpy(reinterpret_cast<char *>(sta_config.sta.ssid), ssid.c_str(),
                 sizeof(sta_config.sta.ssid) - 1);
    std::strncpy(reinterpret_cast<char *>(sta_config.sta.password), password.c_str(),
                 sizeof(sta_config.sta.password) - 1);
    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_config failed: %s", esp_err_to_name(err));
        return httpd_resp_send_500(req);
    }

    ESP_LOGI(TAG, "provisioned for '%s', rebooting into STA mode", ssid.c_str());
    esp_err_t send_err = httpd_resp_send(req, nullptr, 0);
    xTaskCreate(provision_reboot_task, "provision_reboot", 2048, nullptr, tskIDLE_PRIORITY + 1,
                nullptr);
    return send_err;
}

constexpr httpd_uri_t PROVISION_URI = {
    .uri = "/provision",
    .method = HTTP_POST,
    .handler = provision_post_handler,
    .user_ctx = nullptr,
};

// Matches every path (config.uri_match_fn = httpd_uri_match_wildcard, set
// in wifi_provision_start()) — OS captive-portal-detection probes hit
// arbitrary well-known paths, and all of them need to resolve to the
// portal for the OS to actually pop it up.
esp_err_t portal_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, PORTAL_PAGE_BODY, HTTPD_RESP_USE_STRLEN);
}

constexpr httpd_uri_t PORTAL_URI = {
    .uri = "/*",
    .method = HTTP_GET,
    .handler = portal_get_handler,
    .user_ctx = nullptr,
};

// Minimal captive DNS responder: every A query gets the AP's own IP (so a
// client that just resolved "connectivitycheck.something" lands on the
// portal), everything else gets NODATA. No cache, no forwarding, no
// metrics — there's no upstream to forward to in AP mode and nothing here
// is on the hot path dns_server.cpp optimizes for.
void captive_dns_task(void *)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        vTaskDelete(nullptr);
        return;
    }

    sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_port = htons(53);
    if (bind(sock, reinterpret_cast<sockaddr *>(&dest_addr), sizeof(dest_addr)) < 0) {
        ESP_LOGE(TAG, "bind() to port 53 failed: errno %d", errno);
        close(sock);
        vTaskDelete(nullptr);
        return;
    }
    ESP_LOGI(TAG, "captive DNS listening on UDP port 53");

    while (true) {
        std::array<uint8_t, RX_BUFFER_SIZE> rx_buffer;
        sockaddr_in source_addr = {};
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(sock, rx_buffer.data(), rx_buffer.size(), 0,
                            reinterpret_cast<sockaddr *>(&source_addr), &socklen);
        if (len < 0) {
            ESP_LOGE(TAG, "recvfrom() failed: errno %d", errno);
            continue;
        }

        auto header = parse_dns_header(rx_buffer.data(), len);
        if (!header || header->qdcount == 0) {
            continue;
        }
        size_t offset = DNS_HEADER_SIZE;
        auto qname = parse_question_name(rx_buffer.data(), len, offset);
        if (!qname || offset + 4 > static_cast<size_t>(len)) {
            continue;
        }
        uint16_t qtype = read_uint16_be(rx_buffer.data(), offset);
        const uint8_t *question_section = rx_buffer.data() + DNS_HEADER_SIZE;
        size_t question_section_len = (offset + 4) - DNS_HEADER_SIZE;

        uint8_t tx_buffer[TX_BUFFER_SIZE];
        std::optional<size_t> resp_len;
        if (qtype == DNS_TYPE_A) {
            resp_len = build_a_record_response(header->id, header->flags, question_section,
                                                question_section_len, s_ap_ip, tx_buffer,
                                                sizeof(tx_buffer));
        } else {
            // AAAA (or anything else): NODATA, not an A answer and not
            // NXDOMAIN — a bogus AAAA would make a dual-stack client prefer
            // a v6 path to nowhere instead of following the v4 redirect.
            resp_len = build_nodata_response(header->id, header->flags, question_section,
                                              question_section_len, tx_buffer, sizeof(tx_buffer));
        }
        if (resp_len) {
            sendto(sock, tx_buffer, *resp_len, 0, reinterpret_cast<sockaddr *>(&source_addr),
                   socklen);
        }
    }
}

// Polls GPIO0 (BOOT) every 250ms; 20 consecutive low reads (~5s) before
// acting, so a stray transient on the line can't trigger a wipe.
void factory_reset_task(void *)
{
    gpio_config_t io_conf = {};
    io_conf.pin_bit_mask = 1ULL << GPIO_NUM_0;
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pull_up_en = GPIO_PULLUP_ENABLE; // most devkits already pull this up externally too
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&io_conf);

    constexpr int REQUIRED_CONSECUTIVE_LOW = 20;
    int consecutive_low = 0;
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(250));
        if (gpio_get_level(GPIO_NUM_0) != 0) {
            consecutive_low = 0;
            continue;
        }
        if (++consecutive_low >= REQUIRED_CONSECUTIVE_LOW) {
            ESP_LOGW(TAG, "BOOT held ~5s, wiping stored Wi-Fi config and rebooting");
            esp_wifi_restore();
            esp_restart();
        }
    }
}

} // namespace

void wifi_provision_start()
{
    ESP_LOGW(TAG, "no provisioned network reachable, starting portal '%s'", AP_SSID);

    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();

    // Only reached after wifi_connect_sta() already started Wi-Fi in STA
    // mode and its disconnect handler has been retrying esp_wifi_connect()
    // in the background — reconfiguring mode/config on a running stack
    // without stopping it first isn't a supported transition. Ignore
    // ESP_ERR_WIFI_NOT_STARTED (nothing to stop if it somehow wasn't
    // running); anything else is unexpected here and should abort like the
    // rest of this bring-up sequence.
    esp_err_t stop_err = esp_wifi_stop();
    if (stop_err != ESP_OK && stop_err != ESP_ERR_WIFI_NOT_STARTED) {
        ESP_ERROR_CHECK(stop_err);
    }

    // APSTA, not plain AP: esp_wifi_scan_start() (used by /scan) fails in
    // WIFI_MODE_AP — nothing here ever actually associates via the STA
    // interface, it's along for the ride purely so scanning works.
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    wifi_config_t ap_config = {};
    std::strncpy(reinterpret_cast<char *>(ap_config.ap.ssid), AP_SSID,
                 sizeof(ap_config.ap.ssid) - 1);
    ap_config.ap.ssid_len = static_cast<uint8_t>(std::strlen(AP_SSID));
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 4;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_netif_ip_info_t ip_info = {};
    ESP_ERROR_CHECK(esp_netif_get_ip_info(ap_netif, &ip_info));
    uint32_t addr = ip_info.ip.addr;
    s_ap_ip = {static_cast<uint8_t>(addr & 0xFF), static_cast<uint8_t>((addr >> 8) & 0xFF),
               static_cast<uint8_t>((addr >> 16) & 0xFF), static_cast<uint8_t>((addr >> 24) & 0xFF)};
    ESP_LOGI(TAG, "AP up at " IPSTR, IP2STR(&ip_info.ip));

    // The AP's DHCP server doesn't hand out a DNS server by default.
    // Without this, joining clients get no resolver at all, the captive
    // DNS task below never sees a query, and no captive-portal probe ever
    // fires — the DHCP server must be stopped while its options are
    // reconfigured.
    uint8_t dhcps_dns_offer = DHCPS_OFFER_DNS;
    ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
    ESP_ERROR_CHECK(esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
                                            &dhcps_dns_offer, sizeof(dhcps_dns_offer)));
    esp_netif_dns_info_t dns_info = {};
    dns_info.ip.type = ESP_IPADDR_TYPE_V4;
    dns_info.ip.u_addr.ip4 = ip_info.ip;
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns_info));
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));

    // No factory_reset_task here: in AP mode the provisioning portal itself
    // is already the recovery path (see factory_reset_watch_start()'s doc
    // comment) — running the watcher too would just contend over GPIO0 for
    // no benefit.
    xTaskCreate(captive_dns_task, "captive_dns", 4096, nullptr, 5, nullptr);

    httpd_handle_t server = nullptr;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard; // required for the catch-all "/*" portal route
    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &SCAN_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &PROVISION_URI));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &PORTAL_URI));

    ESP_LOGI(TAG, "provisioning portal ready — join '%s' and browse to any URL", AP_SSID);
}

void factory_reset_watch_start()
{
    xTaskCreate(factory_reset_task, "factory_reset_watch", 2048, nullptr, tskIDLE_PRIORITY + 1,
                nullptr);
}
