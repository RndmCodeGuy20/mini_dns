#pragma once

#include <array>

// Curated default ad/tracker domains, used to seed the blocklist on first
// boot (see dns_blocklist.h). Suffix matching means each entry also blocks
// its subdomains (e.g. "doubleclick.net" covers "ads.doubleclick.net") —
// see DnsBlocklist::is_blocked. Editable by reflashing; once seeded, the
// live list lives in NVS and this array is no longer consulted.
constexpr std::array<const char *, 20> DNS_BLOCKLIST_DEFAULTS = {{
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    "adservice.google.com",
    "ads.yahoo.com",
    "advertising.com",
    "scorecardresearch.com",
    "adnxs.com",
    "outbrain.com",
    "taboola.com",
    "criteo.com",
    "quantserve.com",
    "moatads.com",
    "rubiconproject.com",
    "pubmatic.com",
    "adsrvr.org",
    "amazon-adsystem.com",
}};
