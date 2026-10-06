#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "esp_err.h"

// ponytail: hard cap so the set can't eat the internal heap Wi-Fi/lwIP need —
// each entry is a small (<16KB) allocation, so it lands in internal RAM
// before PSRAM (CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL). ~100 bytes/domain
// worst case. Raise it while watching esp_heap_free_bytes, or move the set
// to a PSRAM allocator if a much bigger list is ever needed.
constexpr size_t DNS_BLOCKLIST_MAX_DOMAINS = 1000;

enum class DnsBlocklistResult {
    kOk,
    kNotFound,     // remove(): domain isn't in the set
    kFull,         // add(): would exceed DNS_BLOCKLIST_MAX_DOMAINS
    kPersistFailed // NVS write failed; the in-memory change was rolled back
};

// Domain blocklist consulted after the local static table and before the
// TTL cache/forwarder (see dns_server.cpp and docs/superpowers/specs/
// 2026-07-21-edge-dns-phase2-adblock-design.md). Read by the DNS task on
// every query and, as of Phase 8, mutated by the HTTP task via
// POST/DELETE /api/blocklist — so domains_ is guarded by a std::mutex, the
// same tradeoff DnsRecordStore made in Phase 5. blocks_total_ stays a plain
// atomic outside the lock.
class DnsBlocklist {
public:
    // Loads the domain set from NVS (namespace "blocklist", blob key
    // "domains": a single newline-separated list). Before Phase 8 the list
    // lived in a *string* key "list", which nvs_set_str caps at 4000 bytes
    // (~200 domains); if only that legacy key exists it's read, re-saved as
    // the blob, and erased. If neither exists (first boot), seeds from
    // dns_blocklist_defaults.h and persists via save_to_nvs(). Must be
    // called before the DNS task starts and before the HTTP server starts
    // (see dns_server_start()).
    esp_err_t load_from_nvs();

    // Serializes the current set back to NVS. Called by load_from_nvs() on
    // first-boot seeding/migration, and by add()/remove() while they hold
    // the lock. Callers must hold mutex_ (or be pre-task, at boot).
    esp_err_t save_to_nvs() const;

    // Mutations — HTTP task only. Each locks, mutates, persists, and rolls
    // the in-memory set back if the NVS write fails, so memory and flash
    // never disagree. Domains must already be lowercased and validated.
    // add() takes a batch so a bulk import costs one flash write, not one
    // per domain; already-present domains are skipped, not an error.
    DnsBlocklistResult add(const std::vector<std::string> &domains);
    DnsBlocklistResult remove(const std::string &domain);

    // Suffix match on label boundaries: tests qname_lower, then repeatedly
    // strips the leftmost label and retests (so blocking "doubleclick.net"
    // also blocks "ads.doubleclick.net", but never "notdoubleclick.net").
    // qname_lower must already be lowercased (see lowercase_ascii in
    // dns_cache.h) — this function does no case normalization itself.
    bool is_blocked(const std::string &qname_lower) const;

    // Increments the block counter. Called once per sinkholed query.
    void record_block();

    uint32_t blocks_total() const;
    size_t size() const;

    // Copies the set out under lock, for the HTTP task to serialize without
    // touching domains_ unlocked.
    std::vector<std::string> snapshot() const;

private:
    mutable std::mutex mutex_;
    std::unordered_set<std::string> domains_; // guarded by mutex_
    std::atomic<uint32_t> blocks_total_{0};
};

// Process-wide instance: the DNS task calls is_blocked()/record_block(),
// the HTTP task calls snapshot()/blocks_total()/size()/add()/remove().
DnsBlocklist &blocklist();
