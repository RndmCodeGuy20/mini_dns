#pragma once

#include <optional>
#include <string>

// Parsed "MAJOR.MINOR.PATCH" — a leading 'v'/'V' is stripped by
// ota_version_parse(), matching this repo's `git tag v0.6.0` convention
// (see .github/workflows/ci.yml's release job and esp_app_get_description()
// via PROJECT_VER, which git-describe derives from the same tags).
struct OtaVersion {
    unsigned major = 0;
    unsigned minor = 0;
    unsigned patch = 0;
};

// Strict on major/minor, tolerant on patch: a trailing non-digit suffix
// (e.g. the "-3-gabc1234-dirty" git-describe appends between exact tags)
// is ignored once the leading digits of patch are consumed. Returns
// nullopt for anything that isn't at least "N.N" with digit prefixes,
// e.g. "" or "notaversion".
std::optional<OtaVersion> ota_version_parse(const std::string &text);

// True only if `remote` parses AND is strictly greater than `current`
// under lexicographic (major, minor, patch) comparison. Fails closed:
// if either side doesn't parse, returns false — never OTA onto something
// this comparator couldn't understand.
bool ota_version_is_newer(const std::string &current, const std::string &remote);
