#pragma once

#include <array>
#include <cstdint>

// The hostname -> IPv4 address table. As of Phase 5, this is no longer the
// live table — it's the seed consulted once by DnsRecordStore::load_from_nvs()
// on first boot (no "list" key yet in NVS), the same role
// DNS_BLOCKLIST_DEFAULTS plays for DnsBlocklist (dns_blocklist_defaults.h).
// After that first boot, the live, mutable table lives in NVS and is served
// via dns_record_store.h/.cpp; this array is no longer consulted.
struct dns_record_t {
    const char *hostname;
    std::array<uint8_t, 4> ip;
};

constexpr std::array<dns_record_t, 4> DNS_RECORDS_DEFAULTS = {{
    {"test.loc", {192, 168, 1, 50}},
    {"router.loc", {192, 168, 1, 1}},
    {"nas.loc", {192, 168, 1, 60}},
    {"laptop.loc", {192, 168, 29, 195}},
}};
