#include "dns_cache.h"

#include <algorithm>
#include <cctype>

std::string lowercase_ascii(std::string s)
{
    for (char &c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

namespace {
uint32_t clamp_ttl(uint32_t ttl_seconds)
{
    if (ttl_seconds < 1) {
        return 1;
    }
    if (ttl_seconds > DNS_CACHE_MAX_TTL_SECONDS) {
        return DNS_CACHE_MAX_TTL_SECONDS;
    }
    return ttl_seconds;
}

bool is_expired(const dns_cache_entry_t &entry, int64_t now_ms)
{
    int64_t age_ms = now_ms - entry.inserted_at_ms;
    return age_ms < 0 || age_ms >= static_cast<int64_t>(entry.ttl_seconds) * 1000;
}
} // namespace

DnsCache::DnsCache(size_t capacity) : entries_(capacity) {}

int DnsCache::find_slot(const std::string &qname_lower, uint16_t qtype) const
{
    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto &entry = entries_[i];
        if (entry.occupied && entry.qtype == qtype && entry.qname_lower == qname_lower) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int DnsCache::find_free_or_lru_slot() const
{
    int lru_index = -1;
    int64_t oldest_used_at = 0;

    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto &entry = entries_[i];
        if (!entry.occupied) {
            return static_cast<int>(i);
        }
        if (lru_index < 0 || entry.last_used_at_ms < oldest_used_at) {
            lru_index = static_cast<int>(i);
            oldest_used_at = entry.last_used_at_ms;
        }
    }
    return lru_index; // entries_ is never empty in practice (capacity > 0)
}

const dns_cache_entry_t *DnsCache::lookup(const std::string &qname_lower, uint16_t qtype,
                                          int64_t now_ms)
{
    int index = find_slot(qname_lower, qtype);
    if (index < 0) {
        return nullptr;
    }

    dns_cache_entry_t &entry = entries_[static_cast<size_t>(index)];
    if (is_expired(entry, now_ms)) {
        entry.occupied = false;
        return nullptr;
    }

    entry.last_used_at_ms = now_ms;
    return &entry;
}

void DnsCache::insert(std::string qname_lower, uint16_t qtype, uint16_t rcode, uint16_t ancount,
                      std::vector<uint8_t> answer_section, uint32_t ttl_seconds, int64_t now_ms)
{
    int index = find_slot(qname_lower, qtype);
    if (index < 0) {
        index = find_free_or_lru_slot();
    }
    if (index < 0) {
        return; // capacity == 0; nothing to do
    }

    dns_cache_entry_t &entry = entries_[static_cast<size_t>(index)];
    entry.qname_lower = std::move(qname_lower);
    entry.qtype = qtype;
    entry.rcode = rcode;
    entry.ancount = ancount;
    entry.answer_section = std::move(answer_section);
    entry.ttl_seconds = clamp_ttl(ttl_seconds);
    entry.inserted_at_ms = now_ms;
    entry.last_used_at_ms = now_ms;
    entry.occupied = true;
}

void DnsCache::sweep_expired(int64_t now_ms)
{
    for (auto &entry : entries_) {
        if (entry.occupied && is_expired(entry, now_ms)) {
            entry.occupied = false;
        }
    }
}

size_t DnsCache::size() const
{
    return static_cast<size_t>(
        std::count_if(entries_.begin(), entries_.end(),
                      [](const dns_cache_entry_t &e) { return e.occupied; }));
}
