#include "provision_validate.h"

ProvisionValidation provision_validate(const std::string &ssid, const std::string &password)
{
    // SSID is a max-32-byte field in the 802.11 beacon/probe frames — not
    // a UI choice. Zero-length SSIDs are reserved for the "broadcast" /
    // wildcard case and aren't valid for a network to advertise itself as.
    if (ssid.empty()) {
        return ProvisionValidation::kSsidEmpty;
    }
    if (ssid.size() > 32) {
        return ProvisionValidation::kSsidTooLong;
    }

    // Password: 0 bytes is the open-network case, valid on its own.
    // Anything else must fall in WPA2-PSK's ASCII passphrase range of
    // 8-63 bytes (RSN spec) — 1-7 bytes is neither open nor a legal PSK.
    if (password.empty()) {
        return ProvisionValidation::kOk;
    }
    if (password.size() < 8) {
        return ProvisionValidation::kPasswordTooShort;
    }
    if (password.size() > 63) {
        return ProvisionValidation::kPasswordTooLong;
    }

    return ProvisionValidation::kOk;
}
