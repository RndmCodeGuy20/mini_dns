#include "ota_version.h"

#include <cctype>

namespace {

// Parses a run of ASCII digits starting at `pos`, advancing `pos` past
// them. Returns nullopt if there isn't at least one digit at `pos`.
std::optional<unsigned> parse_uint_component(const std::string &s, size_t &pos)
{
    if (pos >= s.size() || !std::isdigit(static_cast<unsigned char>(s[pos]))) {
        return std::nullopt;
    }
    unsigned value = 0;
    while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) {
        value = value * 10 + static_cast<unsigned>(s[pos] - '0');
        ++pos;
    }
    return value;
}

} // namespace

std::optional<OtaVersion> ota_version_parse(const std::string &text)
{
    size_t pos = 0;
    if (pos < text.size() && (text[pos] == 'v' || text[pos] == 'V')) {
        ++pos;
    }

    auto major = parse_uint_component(text, pos);
    if (!major || pos >= text.size() || text[pos] != '.') {
        return std::nullopt;
    }
    ++pos;

    auto minor = parse_uint_component(text, pos);
    if (!minor) {
        return std::nullopt;
    }

    // Patch is optional-but-expected: "1.2" with no patch component at all
    // is treated as patch=0 rather than rejected, since a missing patch
    // number is still an unambiguous version. A "." with no digits after
    // it (e.g. "1.2.") is rejected as malformed.
    unsigned patch = 0;
    if (pos < text.size() && text[pos] == '.') {
        ++pos;
        auto parsed_patch = parse_uint_component(text, pos);
        if (!parsed_patch) {
            return std::nullopt;
        }
        patch = *parsed_patch;
    }

    return OtaVersion{*major, *minor, patch};
}

bool ota_version_is_newer(const std::string &current, const std::string &remote)
{
    auto cur = ota_version_parse(current);
    auto rem = ota_version_parse(remote);
    if (!cur || !rem) {
        return false;
    }
    if (rem->major != cur->major) {
        return rem->major > cur->major;
    }
    if (rem->minor != cur->minor) {
        return rem->minor > cur->minor;
    }
    return rem->patch > cur->patch;
}
