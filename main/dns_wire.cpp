#include "dns_wire.h"

#include <cstring>

namespace {

// Writes the 12-byte header common to every response this server sends:
// ID echoed, QR=1/AA=1/RD-echoed/RCODE=rcode, QDCOUNT=1 (we always echo
// exactly one question), NSCOUNT=0, ARCOUNT=0.
void write_dns_response_header(uint8_t *buf, uint16_t query_id, uint16_t query_flags,
                                uint16_t ancount, uint16_t rcode)
{
    write_uint16_be(buf, 0, query_id);
    write_uint16_be(buf, 2, (0x8400 | (query_flags & 0x0100)) | (rcode & 0x000F));
    write_uint16_be(buf, 4, 1); // QDCOUNT
    write_uint16_be(buf, 6, ancount);
    write_uint16_be(buf, 8, 0); // NSCOUNT
    write_uint16_be(buf, 10, 0); // ARCOUNT
}

} // namespace

// DNS wire integers are always big-endian regardless of host/target
// endianness; packed by hand (rather than via ntohs/htons) so this file
// has no platform-header dependency, matching its "pure, host-testable"
// contract.
uint16_t read_uint16_be(const uint8_t *buf, size_t offset)
{
    return (static_cast<uint16_t>(buf[offset]) << 8) | static_cast<uint16_t>(buf[offset + 1]);
}

uint32_t read_uint32_be(const uint8_t *buf, size_t offset)
{
    return (static_cast<uint32_t>(buf[offset]) << 24) |
           (static_cast<uint32_t>(buf[offset + 1]) << 16) |
           (static_cast<uint32_t>(buf[offset + 2]) << 8) | static_cast<uint32_t>(buf[offset + 3]);
}

void write_uint16_be(uint8_t *buf, size_t offset, uint16_t value)
{
    buf[offset] = static_cast<uint8_t>(value >> 8);
    buf[offset + 1] = static_cast<uint8_t>(value & 0xFF);
}

void write_uint32_be(uint8_t *buf, size_t offset, uint32_t value)
{
    buf[offset] = static_cast<uint8_t>(value >> 24);
    buf[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buf[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buf[offset + 3] = static_cast<uint8_t>(value & 0xFF);
}

std::optional<dns_header_t> parse_dns_header(const uint8_t *buf, size_t len)
{
    if (len < DNS_HEADER_SIZE) {
        return std::nullopt;
    }
    dns_header_t header;
    header.id = read_uint16_be(buf, 0);
    header.flags = read_uint16_be(buf, 2);
    header.qdcount = read_uint16_be(buf, 4);
    header.ancount = read_uint16_be(buf, 6);
    header.nscount = read_uint16_be(buf, 8);
    header.arcount = read_uint16_be(buf, 10);
    return header;
}

std::optional<std::string> parse_question_name(const uint8_t *buf, size_t len, size_t &offset)
{
    std::string name;

    while (true) {
        if (offset >= len) {
            return std::nullopt;
        }

        uint8_t label_len = buf[offset];

        if ((label_len & 0xC0) != 0) {
            return std::nullopt;
        }

        offset += 1;

        if (label_len == 0) {
            break;
        }

        if (offset + label_len > len) {
            return std::nullopt;
        }

        if (!name.empty()) {
            name += '.';
        }
        name.append(reinterpret_cast<const char *>(buf + offset), label_len);
        offset += label_len;

        if (name.size() > DNS_QNAME_MAX_LENGTH) {
            return std::nullopt;
        }
    }

    return name;
}

bool skip_name(const uint8_t *buf, size_t len, size_t &offset)
{
    while (true) {
        if (offset >= len) {
            return false;
        }

        uint8_t label_len = buf[offset];

        if ((label_len & 0xC0) == 0xC0) {
            // Compression pointer: 2 bytes, and the name ends here — we
            // don't need to follow it, only skip past it.
            if (offset + 2 > len) {
                return false;
            }
            offset += 2;
            return true;
        }

        if ((label_len & 0xC0) != 0) {
            return false; // reserved top-bit combination
        }

        offset += 1;

        if (label_len == 0) {
            return true; // root label, name ends here
        }

        if (offset + label_len > len) {
            return false;
        }
        offset += label_len;
    }
}

std::optional<answer_section_scan_t> scan_answer_section(const uint8_t *buf, size_t len,
                                                          size_t answer_start_offset,
                                                          uint16_t ancount)
{
    size_t offset = answer_start_offset;
    uint32_t min_ttl = 0;
    bool have_ttl = false;

    for (uint16_t i = 0; i < ancount; ++i) {
        if (!skip_name(buf, len, offset)) {
            return std::nullopt;
        }
        if (offset + DNS_ANSWER_RR_FIXED_SIZE > len) {
            return std::nullopt;
        }
        uint32_t ttl = read_uint32_be(buf, offset + 4);
        uint16_t rdlength = read_uint16_be(buf, offset + 8);
        offset += DNS_ANSWER_RR_FIXED_SIZE;

        if (offset + rdlength > len) {
            return std::nullopt;
        }
        offset += rdlength;

        if (!have_ttl || ttl < min_ttl) {
            min_ttl = ttl;
            have_ttl = true;
        }
    }

    return answer_section_scan_t{offset, min_ttl};
}

const char *qtype_to_string(uint16_t qtype)
{
    switch (qtype) {
        case DNS_TYPE_A:
            return "A";
        case 28:
            return "AAAA";
        default:
            return "OTHER";
    }
}

std::optional<size_t> build_a_record_response(uint16_t query_id, uint16_t query_flags,
                                               const uint8_t *question_section,
                                               size_t question_section_len,
                                               const std::array<uint8_t, 4> &ip,
                                               uint8_t *tx_buffer, size_t tx_capacity)
{
    constexpr size_t DNS_ANSWER_RR_SIZE = 16; // 2 name-ptr + 2 type + 2 class + 4 ttl + 2 rdlength + 4 rdata
    const size_t total_len = DNS_HEADER_SIZE + question_section_len + DNS_ANSWER_RR_SIZE;
    if (total_len > tx_capacity) {
        return std::nullopt;
    }

    write_dns_response_header(tx_buffer, query_id, query_flags, /*ancount=*/1, DNS_RCODE_NOERROR);
    std::memcpy(tx_buffer + DNS_HEADER_SIZE, question_section, question_section_len);

    size_t offset = DNS_HEADER_SIZE + question_section_len;
    write_uint16_be(tx_buffer, offset, DNS_NAME_COMPRESSION_POINTER);
    offset += 2;
    write_uint16_be(tx_buffer, offset, DNS_TYPE_A);
    offset += 2;
    write_uint16_be(tx_buffer, offset, DNS_CLASS_IN);
    offset += 2;
    write_uint32_be(tx_buffer, offset, 60); // ANSWER_TTL_SECONDS, matches prior behavior
    offset += 4;
    write_uint16_be(tx_buffer, offset, static_cast<uint16_t>(ip.size()));
    offset += 2;
    std::memcpy(tx_buffer + offset, ip.data(), ip.size());
    offset += ip.size();

    return offset;
}

std::optional<size_t> build_nxdomain_response(uint16_t query_id, uint16_t query_flags,
                                               const uint8_t *question_section,
                                               size_t question_section_len, uint8_t *tx_buffer,
                                               size_t tx_capacity)
{
    const size_t total_len = DNS_HEADER_SIZE + question_section_len;
    if (total_len > tx_capacity) {
        return std::nullopt;
    }

    write_dns_response_header(tx_buffer, query_id, query_flags, /*ancount=*/0,
                               DNS_RCODE_NXDOMAIN);
    std::memcpy(tx_buffer + DNS_HEADER_SIZE, question_section, question_section_len);

    return total_len;
}

std::optional<size_t> build_relayed_response(uint16_t query_id, uint16_t query_flags,
                                              const uint8_t *question_section,
                                              size_t question_section_len, uint16_t rcode,
                                              uint16_t ancount, const uint8_t *answer_section,
                                              size_t answer_section_len, uint8_t *tx_buffer,
                                              size_t tx_capacity)
{
    const size_t total_len = DNS_HEADER_SIZE + question_section_len + answer_section_len;
    if (total_len > tx_capacity) {
        return std::nullopt;
    }

    write_dns_response_header(tx_buffer, query_id, query_flags, ancount, rcode);
    std::memcpy(tx_buffer + DNS_HEADER_SIZE, question_section, question_section_len);
    if (answer_section_len > 0) {
        std::memcpy(tx_buffer + DNS_HEADER_SIZE + question_section_len, answer_section,
                    answer_section_len);
    }

    return total_len;
}
