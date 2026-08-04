#pragma once

#include <string>

// Result of validating a SoftAP-provisioned SSID/password pair against
// hard 802.11 / WPA2-PSK limits (not arbitrary policy — see
// provision_validate.cpp for the byte-length rationale on each boundary).
enum class ProvisionValidation {
    kOk,
    kSsidEmpty,
    kSsidTooLong,
    kPasswordTooShort,
    kPasswordTooLong,
};

// Pure function — no IDF/FreeRTOS headers — so this links into host_test/
// (linux target) without pulling in ESP-IDF wifi headers. Lengths are
// byte lengths (std::string::size()), not codepoints: the 802.11 spec's
// SSID/password limits are byte limits.
ProvisionValidation provision_validate(const std::string &ssid, const std::string &password);
