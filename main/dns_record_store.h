#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "esp_err.h"

// A runtime record — unlike dns_record_t (dns_records.h), hostname is owned
// storage (std::string), since entries are created/edited/deleted at
// runtime rather than baked in at compile time.
//
// A name may hold an A, an AAAA, or both (Phase 6 dual-stack) — never
// neither: create()/update() reject a request supplying no address.
struct DnsRecordEntry {
    std::string hostname;
    std::optional<std::array<uint8_t, 4>> ipv4;
    std::optional<std::array<uint8_t, 16>> ipv6;
};

// Upper bound on the number of records, so a misbehaving/malicious client
// can't grow the table without limit — see create()'s "full" result.
constexpr size_t DNS_RECORD_STORE_MAX_RECORDS = 64;

enum class DnsRecordStoreResult {
    kOk,
    kAlreadyExists, // create(): a record for this hostname already exists
    kNotFound,      // update()/remove(): no record for this hostname
    kFull,          // create(): at DNS_RECORD_STORE_MAX_RECORDS capacity
    kNoAddress,     // create()/update(): neither ipv4 nor ipv6 supplied
};

// The DNS record table (Phase 5) — unlike DnsCache/DnsForwarder (single-owner,
// no mutex) or DnsBlocklist/DnsMetrics (cross-task but either immutable-after-
// boot or a single atomic word), this is the codebase's first genuinely
// shared *mutable* state: the DNS task reads it on every query while the HTTP
// task rewrites it on CRUD calls. A plain std::mutex guards every access —
// see ARCHITECTURE.md's concurrency section for why that tradeoff was made
// over a lock-free alternative.
class DnsRecordStore {
public:
    // Loads the record table from NVS (namespace "records", key "list": a
    // single newline-separated "hostname=A.B.C.D" blob — same one-blob-not-
    // one-key-per-entry shape as DnsBlocklist, since NVS key names cap at 15
    // characters). If the key doesn't exist yet (first boot), seeds from
    // DNS_RECORDS_DEFAULTS (dns_records.h) and persists via save_to_nvs(), so
    // every later boot loads from NVS instead of the compiled-in table.
    esp_err_t load_from_nvs();

    // Serializes the current table back to the same NVS blob. Called by
    // load_from_nvs() on first-boot seeding, and by every mutation below
    // while still holding the lock.
    esp_err_t save_to_nvs() const;

    // Case-insensitive lookup for the DNS task's hot path. Returns a copy of
    // the whole entry, never a pointer or reference — the lock is released
    // before this returns, so a dangling pointer into records_ must be
    // impossible. Returning the whole entry (rather than just an address)
    // lets the caller distinguish "name exists but not for this qtype"
    // (NODATA) from "name doesn't exist" (NXDOMAIN) — see dns_server.cpp.
    std::optional<DnsRecordEntry> find(const std::string &hostname) const;

    // Copies the whole table out under lock, for the HTTP task's GET
    // /api/records handler to serialize without touching records_ unlocked.
    std::vector<DnsRecordEntry> snapshot() const;

    // Mutations — HTTP task only. Each locks, mutates, and persists via
    // save_to_nvs() while still holding the lock, so a reader can never
    // observe an in-memory table that doesn't match what's on flash.
    //
    // create()/update() take the full desired address set for the record
    // (PUT semantics: update() replaces both families wholesale rather than
    // patching one). Callers must supply at least one of ipv4/ipv6 — the
    // HTTP layer enforces this before calling in (see http_server.cpp), but
    // both methods also refuse an all-nullopt pair defensively.
    DnsRecordStoreResult create(const std::string &hostname,
                                 const std::optional<std::array<uint8_t, 4>> &ipv4,
                                 const std::optional<std::array<uint8_t, 16>> &ipv6);
    DnsRecordStoreResult update(const std::string &hostname,
                                 const std::optional<std::array<uint8_t, 4>> &ipv4,
                                 const std::optional<std::array<uint8_t, 16>> &ipv6);
    DnsRecordStoreResult remove(const std::string &hostname);

private:
    mutable std::mutex mutex_;
    std::vector<DnsRecordEntry> records_; // guarded by mutex_

    // Callers must already hold mutex_.
    int find_index_locked(const std::string &hostname) const;
};

// Process-wide singleton, same shape as blocklist()/metrics(). The DNS task
// calls find(); the HTTP task calls snapshot()/create()/update()/remove().
DnsRecordStore &record_store();
