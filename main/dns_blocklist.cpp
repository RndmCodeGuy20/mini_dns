#include "dns_blocklist.h"

#include <sstream>

#include "dns_blocklist_defaults.h"
#include "esp_log.h"
#include "nvs.h"

namespace {

constexpr const char *TAG = "dns_blocklist";
constexpr const char *NVS_NAMESPACE = "blocklist";
constexpr const char *NVS_KEY_LIST = "list";

// Serializes a domain set to a single newline-separated blob — one NVS
// value rather than one key per domain, since NVS key names are capped at
// 15 characters and a domain can exceed that.
std::string serialize(const std::unordered_set<std::string> &domains)
{
    std::ostringstream out;
    for (const auto &domain : domains) {
        out << domain << '\n';
    }
    return out.str();
}

std::unordered_set<std::string> deserialize(const std::string &blob)
{
    std::unordered_set<std::string> domains;
    std::istringstream in(blob);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            domains.insert(line);
        }
    }
    return domains;
}

} // namespace

esp_err_t DnsBlocklist::load_from_nvs()
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open() failed: %s", esp_err_to_name(err));
        return err;
    }

    size_t required_size = 0;
    err = nvs_get_str(handle, NVS_KEY_LIST, nullptr, &required_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // First boot: seed from the baked-in defaults and persist them, so
        // every later boot loads from NVS instead of this compiled-in list.
        domains_.clear();
        for (const char *domain : DNS_BLOCKLIST_DEFAULTS) {
            domains_.insert(domain);
        }
        nvs_close(handle);
        ESP_LOGI(TAG, "no NVS blocklist found, seeding %u default domain(s)",
                 static_cast<unsigned>(domains_.size()));
        return save_to_nvs();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_get_str() size query failed: %s", esp_err_to_name(err));
        nvs_close(handle);
        return err;
    }

    std::string blob(required_size, '\0');
    err = nvs_get_str(handle, NVS_KEY_LIST, blob.data(), &required_size);
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_get_str() read failed: %s", esp_err_to_name(err));
        return err;
    }
    // required_size includes the NUL terminator; drop the trailing NUL(s)
    // std::string's own storage would otherwise retain.
    if (!blob.empty() && blob.back() == '\0') {
        blob.resize(blob.size() - 1);
    }

    domains_ = deserialize(blob);
    ESP_LOGI(TAG, "loaded %u domain(s) from NVS", static_cast<unsigned>(domains_.size()));
    return ESP_OK;
}

esp_err_t DnsBlocklist::save_to_nvs() const
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open() failed: %s", esp_err_to_name(err));
        return err;
    }

    std::string blob = serialize(domains_);
    err = nvs_set_str(handle, NVS_KEY_LIST, blob.c_str());
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to persist blocklist: %s", esp_err_to_name(err));
    }
    return err;
}

bool DnsBlocklist::is_blocked(const std::string &qname_lower) const
{
    size_t start = 0;
    while (start < qname_lower.size()) {
        std::string suffix = qname_lower.substr(start);
        if (domains_.count(suffix) > 0) {
            return true;
        }
        size_t dot = qname_lower.find('.', start);
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    return false;
}

void DnsBlocklist::record_block()
{
    blocks_total_.fetch_add(1, std::memory_order_relaxed);
}

uint32_t DnsBlocklist::blocks_total() const
{
    return blocks_total_.load(std::memory_order_relaxed);
}

size_t DnsBlocklist::size() const
{
    return domains_.size();
}

const std::unordered_set<std::string> &DnsBlocklist::domains() const
{
    return domains_;
}

DnsBlocklist &blocklist()
{
    static DnsBlocklist instance;
    return instance;
}
