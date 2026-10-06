#include "dns_blocklist.h"

#include <sstream>

#include "dns_blocklist_defaults.h"
#include "esp_log.h"
#include "nvs.h"

namespace {

constexpr const char *TAG = "dns_blocklist";
constexpr const char *NVS_NAMESPACE = "blocklist";
constexpr const char *NVS_KEY_DOMAINS = "domains"; // blob (Phase 8+)
constexpr const char *NVS_KEY_LEGACY_LIST = "list"; // string, pre-Phase 8

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

// Reads one NVS value into `out`, as a blob or as a string. Returns the
// NVS error unchanged, including ESP_ERR_NVS_NOT_FOUND.
esp_err_t read_nvs_value(nvs_handle_t handle, const char *key, bool as_blob, std::string &out)
{
    size_t size = 0;
    esp_err_t err = as_blob ? nvs_get_blob(handle, key, nullptr, &size)
                            : nvs_get_str(handle, key, nullptr, &size);
    if (err != ESP_OK) {
        return err;
    }
    out.assign(size, '\0');
    err = as_blob ? nvs_get_blob(handle, key, out.data(), &size)
                  : nvs_get_str(handle, key, out.data(), &size);
    // nvs_get_str's size includes the NUL terminator; drop it.
    if (err == ESP_OK && !as_blob && !out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return err;
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

    std::string blob;
    err = read_nvs_value(handle, NVS_KEY_DOMAINS, /*as_blob=*/true, blob);
    if (err == ESP_OK) {
        nvs_close(handle);
        domains_ = deserialize(blob);
        ESP_LOGI(TAG, "loaded %u domain(s) from NVS", static_cast<unsigned>(domains_.size()));
        return ESP_OK;
    }
    if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "reading blocklist blob failed: %s", esp_err_to_name(err));
        nvs_close(handle);
        return err;
    }

    // No blob yet: either a pre-Phase 8 device (legacy string key) or a
    // first boot. Both end with save_to_nvs() writing the blob.
    err = read_nvs_value(handle, NVS_KEY_LEGACY_LIST, /*as_blob=*/false, blob);
    if (err == ESP_OK) {
        domains_ = deserialize(blob);
        nvs_close(handle);
        ESP_LOGI(TAG, "migrating %u domain(s) from legacy string key",
                 static_cast<unsigned>(domains_.size()));
        esp_err_t save_err = save_to_nvs();
        if (save_err != ESP_OK) {
            return save_err; // legacy key left intact; migration retries next boot
        }
        if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
            nvs_erase_key(handle, NVS_KEY_LEGACY_LIST);
            nvs_commit(handle);
            nvs_close(handle);
        }
        return ESP_OK;
    }
    nvs_close(handle);
    if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "reading legacy blocklist failed: %s", esp_err_to_name(err));
        return err;
    }

    // First boot: seed from the baked-in defaults and persist them, so
    // every later boot loads from NVS instead of this compiled-in list.
    domains_.clear();
    for (const char *domain : DNS_BLOCKLIST_DEFAULTS) {
        domains_.insert(domain);
    }
    ESP_LOGI(TAG, "no NVS blocklist found, seeding %u default domain(s)",
             static_cast<unsigned>(domains_.size()));
    return save_to_nvs();
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
    if (blob.empty()) {
        blob = "\n"; // never a zero-length blob; deserialize() skips blank lines
    }
    err = nvs_set_blob(handle, NVS_KEY_DOMAINS, blob.data(), blob.size());
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to persist blocklist: %s", esp_err_to_name(err));
    }
    return err;
}

DnsBlocklistResult DnsBlocklist::add(const std::vector<std::string> &domains)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> inserted;
    for (const auto &domain : domains) {
        if (domains_.count(domain) > 0) {
            continue;
        }
        if (domains_.size() >= DNS_BLOCKLIST_MAX_DOMAINS) {
            for (const auto &d : inserted) {
                domains_.erase(d);
            }
            return DnsBlocklistResult::kFull;
        }
        domains_.insert(domain);
        inserted.push_back(domain);
    }
    if (inserted.empty()) {
        return DnsBlocklistResult::kOk;
    }
    if (save_to_nvs() != ESP_OK) {
        for (const auto &d : inserted) {
            domains_.erase(d);
        }
        return DnsBlocklistResult::kPersistFailed;
    }
    return DnsBlocklistResult::kOk;
}

DnsBlocklistResult DnsBlocklist::remove(const std::string &domain)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (domains_.erase(domain) == 0) {
        return DnsBlocklistResult::kNotFound;
    }
    if (save_to_nvs() != ESP_OK) {
        domains_.insert(domain);
        return DnsBlocklistResult::kPersistFailed;
    }
    return DnsBlocklistResult::kOk;
}

bool DnsBlocklist::is_blocked(const std::string &qname_lower) const
{
    std::lock_guard<std::mutex> lock(mutex_);
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
    std::lock_guard<std::mutex> lock(mutex_);
    return domains_.size();
}

std::vector<std::string> DnsBlocklist::snapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return {domains_.begin(), domains_.end()};
}

DnsBlocklist &blocklist()
{
    static DnsBlocklist instance;
    return instance;
}
