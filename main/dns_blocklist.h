#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <unordered_set>

#include "esp_err.h"

// Domain blocklist consulted after the local static table and before the
// TTL cache/forwarder (see dns_server.cpp and docs/superpowers/specs/
// 2026-07-21-edge-dns-phase2-adblock-design.md). Unlike DnsCache, this is
// deliberately readable from both the DNS task and the HTTP task: the
// domain set is populated once at boot (load_from_nvs()) and never mutated
// afterward, so concurrent reads need no synchronization. The only value
// that changes at runtime is blocks_total_, which is a plain atomic counter
// rather than a structure needing a lock.
class DnsBlocklist {
public:
    // Loads the domain set from NVS (namespace "blocklist", key "list": a
    // single newline-separated blob). If the key doesn't exist yet (first
    // boot), seeds the in-memory set from dns_blocklist_defaults.h and
    // persists it via save_to_nvs(), so every later boot loads from NVS
    // instead of the compiled-in list. Must be called before the DNS task
    // starts and before the HTTP server starts (see dns_server_start()).
    esp_err_t load_from_nvs();

    // Serializes the current set back to the same NVS blob. Called by
    // load_from_nvs() on first-boot seeding; also the hook a future HTTP
    // mutate endpoint would call after editing the set.
    esp_err_t save_to_nvs() const;

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
    const std::unordered_set<std::string> &domains() const;

private:
    std::unordered_set<std::string> domains_;
    std::atomic<uint32_t> blocks_total_{0};
};

// Process-wide instance: the DNS task calls is_blocked()/record_block(),
// the HTTP task's /api/blocklist handler calls domains()/blocks_total().
// Both only read domains_ after boot (see class comment above).
DnsBlocklist &blocklist();
