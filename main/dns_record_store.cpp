#include "dns_record_store.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "dns_records.h"
#include "esp_log.h"
#include "nvs.h"

namespace {

constexpr const char *TAG = "dns_record_store";
constexpr const char *NVS_NAMESPACE = "records";
constexpr const char *NVS_KEY_LIST = "list";

std::string ip_to_string(const std::array<uint8_t, 4> &ip)
{
    char buf[16]; // "255.255.255.255" + NUL
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return std::string(buf);
}

// Parses "A.B.C.D" strictly: four decimal octets 0-255, no leading zeros
// beyond a single "0", nothing else on the line. Used only for records this
// store itself serialized, so a parse failure here means NVS corruption, not
// user input — logged and the entry dropped rather than aborting the load.
std::optional<std::array<uint8_t, 4>> parse_ip(const std::string &s)
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

// One "hostname=A.B.C.D" line per record, matching DnsBlocklist's single-blob
// (not one-key-per-entry) NVS shape for the same reason: NVS key names cap
// at 15 characters, well short of a domain name.
std::string serialize(const std::vector<DnsRecordEntry> &records)
{
    std::ostringstream out;
    for (const auto &record : records) {
        out << record.hostname << '=' << ip_to_string(record.ip) << '\n';
    }
    return out.str();
}

std::vector<DnsRecordEntry> deserialize(const std::string &blob)
{
    std::vector<DnsRecordEntry> records;
    std::istringstream in(blob);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        auto ip = parse_ip(line.substr(eq + 1));
        if (!ip) {
            continue;
        }
        records.push_back({line.substr(0, eq), *ip});
    }
    return records;
}

bool ascii_case_insensitive_equal(const std::string &a, const std::string &b)
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

} // namespace

esp_err_t DnsRecordStore::load_from_nvs()
{
    std::lock_guard<std::mutex> lock(mutex_);

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open() failed: %s", esp_err_to_name(err));
        return err;
    }

    size_t required_size = 0;
    err = nvs_get_str(handle, NVS_KEY_LIST, nullptr, &required_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // First boot: seed from the compiled-in defaults and persist them,
        // so every later boot loads from NVS instead of this array.
        records_.clear();
        for (const auto &def : DNS_RECORDS_DEFAULTS) {
            records_.push_back({def.hostname, def.ip});
        }
        nvs_close(handle);
        ESP_LOGI(TAG, "no NVS record table found, seeding %u default record(s)",
                 static_cast<unsigned>(records_.size()));
        std::string blob = serialize(records_);
        esp_err_t save_err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
        if (save_err != ESP_OK) {
            ESP_LOGE(TAG, "nvs_open() for seed save failed: %s", esp_err_to_name(save_err));
            return save_err;
        }
        save_err = nvs_set_str(handle, NVS_KEY_LIST, blob.c_str());
        if (save_err == ESP_OK) {
            save_err = nvs_commit(handle);
        }
        nvs_close(handle);
        if (save_err != ESP_OK) {
            ESP_LOGE(TAG, "failed to persist seeded record table: %s", esp_err_to_name(save_err));
        }
        return save_err;
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

    records_ = deserialize(blob);
    ESP_LOGI(TAG, "loaded %u record(s) from NVS", static_cast<unsigned>(records_.size()));
    return ESP_OK;
}

esp_err_t DnsRecordStore::save_to_nvs() const
{
    // Callers (create/update/remove) already hold mutex_ — this reads
    // records_ under that same lock, so no separate locking here.
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open() failed: %s", esp_err_to_name(err));
        return err;
    }

    std::string blob = serialize(records_);
    err = nvs_set_str(handle, NVS_KEY_LIST, blob.c_str());
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to persist record table: %s", esp_err_to_name(err));
    }
    return err;
}

int DnsRecordStore::find_index_locked(const std::string &hostname) const
{
    for (size_t i = 0; i < records_.size(); ++i) {
        if (ascii_case_insensitive_equal(records_[i].hostname, hostname)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

std::optional<std::array<uint8_t, 4>> DnsRecordStore::find(const std::string &hostname) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    int idx = find_index_locked(hostname);
    if (idx < 0) {
        return std::nullopt;
    }
    return records_[static_cast<size_t>(idx)].ip; // copy — lock released on return
}

std::vector<DnsRecordEntry> DnsRecordStore::snapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return records_; // copy
}

DnsRecordStoreResult DnsRecordStore::create(const std::string &hostname,
                                             const std::array<uint8_t, 4> &ip)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (find_index_locked(hostname) >= 0) {
        return DnsRecordStoreResult::kAlreadyExists;
    }
    if (records_.size() >= DNS_RECORD_STORE_MAX_RECORDS) {
        return DnsRecordStoreResult::kFull;
    }
    records_.push_back({hostname, ip});
    save_to_nvs();
    return DnsRecordStoreResult::kOk;
}

DnsRecordStoreResult DnsRecordStore::update(const std::string &hostname,
                                             const std::array<uint8_t, 4> &ip)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int idx = find_index_locked(hostname);
    if (idx < 0) {
        return DnsRecordStoreResult::kNotFound;
    }
    records_[static_cast<size_t>(idx)].ip = ip;
    save_to_nvs();
    return DnsRecordStoreResult::kOk;
}

DnsRecordStoreResult DnsRecordStore::remove(const std::string &hostname)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int idx = find_index_locked(hostname);
    if (idx < 0) {
        return DnsRecordStoreResult::kNotFound;
    }
    records_.erase(records_.begin() + idx);
    save_to_nvs();
    return DnsRecordStoreResult::kOk;
}

DnsRecordStore &record_store()
{
    static DnsRecordStore instance;
    return instance;
}
