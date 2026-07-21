#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dns_wire.h"

// TTL cache for forwarded upstream DNS answers. Single-owner by design:
// every call is expected to come from the DNS task's select() loop (see
// dns_server.cpp), matching the codebase's existing "no shared mutable
// state between tasks" property — there is deliberately no mutex here.
//
// Entries store the answer section only (RR bytes past the question,
// authority/additional sections dropped — see scan_answer_section),
// which build_relayed_response() splices back behind a fresh
// header/question on a hit. See docs/superpowers/specs/
// 2026-07-21-edge-dns-phase1-design.md for why that's wire-format-safe.

// Sized for the PSRAM this device has (see sdkconfig.defaults); if PSRAM
// isn't actually present at boot (main.cpp logs this), entries still
// live fine in internal SRAM at this capacity — just with less headroom
// for everything else running concurrently.
constexpr size_t DNS_CACHE_CAPACITY = 2048;

// Negative (NXDOMAIN/NODATA) entries are capped independently of
// whatever TTL upstream implies, per RFC 2308 guidance — an upstream
// asserting a very long negative TTL shouldn't lock a name out
// indefinitely.
constexpr uint32_t DNS_NEGATIVE_CACHE_TTL_SECONDS = 60;

// Positive entries are also capped, so a misbehaving upstream can't pin
// an entry far longer than is useful on a device with no way to purge it
// early.
constexpr uint32_t DNS_CACHE_MAX_TTL_SECONDS = 3600;

// Lowercases ASCII letters only (DNS names are ASCII); used to build a
// case-insensitive cache key, matching the existing case-insensitive
// matching semantics in find_dns_record.
std::string lowercase_ascii(std::string s);

struct dns_cache_entry_t {
    std::string qname_lower;
    uint16_t qtype = 0;
    uint16_t rcode = DNS_RCODE_NOERROR;
    uint16_t ancount = 0;
    std::vector<uint8_t> answer_section;
    uint32_t ttl_seconds = 0;
    int64_t inserted_at_ms = 0;
    int64_t last_used_at_ms = 0;
    bool occupied = false;
};

class DnsCache {
public:
    explicit DnsCache(size_t capacity = DNS_CACHE_CAPACITY);

    // Returns the entry for (qname_lower, qtype) if present and not
    // expired as of now_ms, else nullptr. Refreshes LRU recency on hit.
    const dns_cache_entry_t *lookup(const std::string &qname_lower, uint16_t qtype,
                                    int64_t now_ms);

    // Inserts or overwrites the entry for (qname_lower, qtype). ttl_seconds
    // is clamped to [1, DNS_CACHE_MAX_TTL_SECONDS] (callers pass
    // DNS_NEGATIVE_CACHE_TTL_SECONDS directly for negative entries, which
    // falls within that range). Evicts the least-recently-used occupied
    // slot when at capacity and inserting a new key.
    void insert(std::string qname_lower, uint16_t qtype, uint16_t rcode, uint16_t ancount,
                std::vector<uint8_t> answer_section, uint32_t ttl_seconds, int64_t now_ms);

    // Frees slots for entries expired as of now_ms. Not required for
    // correctness (lookup() already treats expired entries as misses),
    // but bounds memory for keys that are never looked up again — call
    // periodically from the DNS task's select() timeout tick.
    void sweep_expired(int64_t now_ms);

    size_t size() const;
    size_t capacity() const { return entries_.size(); }

private:
    // Deliberately linear scan, matching find_dns_record's existing
    // style: at this capacity the scan cost is microseconds, and it
    // avoids pulling in a hash-map's complexity for a device where query
    // volume is modest (a handful of LAN clients, not a public resolver).
    std::vector<dns_cache_entry_t> entries_;

    int find_slot(const std::string &qname_lower, uint16_t qtype) const;
    int find_free_or_lru_slot() const;
};
