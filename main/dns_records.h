#pragma once

#include <array>
#include <cstdint>

// The hardcoded hostname -> IPv4 address table. Compile-time constant,
// read-only after boot — there is no add/edit/delete API by design.
struct dns_record_t {
    const char *hostname;
    std::array<uint8_t, 4> ip;
};

constexpr std::array<dns_record_t, 5> DNS_RECORDS = {{
    {"test.loc", {192, 168, 1, 50}},
    {"router.loc", {192, 168, 1, 1}},
    {"nas.loc", {192, 168, 1, 60}},
    {"laptop.loc", {192, 168, 29, 195}},
}};
