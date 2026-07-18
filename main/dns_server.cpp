#include "dns_server.h"

#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <optional>
#include <string>

#include "dns_records.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

namespace {

constexpr const char *TAG = "dns_server";
constexpr uint16_t DNS_PORT = 53;
constexpr size_t RX_BUFFER_SIZE = 512;
constexpr size_t DNS_HEADER_SIZE = 12;
constexpr size_t DNS_QNAME_MAX_LENGTH = 255;
constexpr uint16_t DNS_TYPE_A = 1;
constexpr uint16_t DNS_CLASS_IN = 1;
constexpr uint16_t DNS_NAME_COMPRESSION_POINTER = 0xC00C; // pointer to offset 12 (question name)
constexpr size_t DNS_ANSWER_RR_SIZE = 16; // 2 name-ptr + 2 type + 2 class + 4 ttl + 2 rdlength + 4 rdata
constexpr uint32_t ANSWER_TTL_SECONDS = 60;
constexpr uint16_t DNS_RCODE_NOERROR = 0;
constexpr uint16_t DNS_RCODE_NXDOMAIN = 3;

struct dns_header_t {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

uint16_t read_uint16_be(const uint8_t *buf, size_t offset)
{
    uint16_t value;
    std::memcpy(&value, buf + offset, sizeof(value));
    return ntohs(value);
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

// Walks the length-prefixed labels of a question-section QNAME starting at
// `offset`, advancing it past the terminating zero-length label. Name
// compression pointers are rejected rather than followed: real queries never
// use them in the question section, and doing so would let untrusted length
// bytes drive further reads into unrelated buffer regions.
std::optional<std::string> parse_question_name(const uint8_t *buf, size_t len, size_t &offset)
{
    std::string name;

    while (true) {
        if (offset >= len) {
            return std::nullopt;
        }

        uint8_t label_len = buf[offset];

        if ((label_len & 0xC0) != 0) {
            ESP_LOGW(TAG, "compression pointer in question name, unsupported");
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

void write_uint16_be(uint8_t *buf, size_t offset, uint16_t value)
{
    uint16_t network_value = htons(value);
    std::memcpy(buf + offset, &network_value, sizeof(network_value));
}

void write_uint32_be(uint8_t *buf, size_t offset, uint32_t value)
{
    uint32_t network_value = htonl(value);
    std::memcpy(buf + offset, &network_value, sizeof(network_value));
}

bool ascii_case_insensitive_equal(const std::string &a, const char *b)
{
    size_t b_len = std::strlen(b);
    if (a.size() != b_len) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

const dns_record_t *find_dns_record(const std::string &hostname)
{
    for (const auto &record : DNS_RECORDS) {
        if (ascii_case_insensitive_equal(hostname, record.hostname)) {
            return &record;
        }
    }
    return nullptr;
}

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

// Builds a DNS response echoing the request's question section verbatim,
// followed by a single A-record answer that uses a compression pointer
// back to the question name (always at offset 12, since the question is
// always the first thing written after the header). Returns std::nullopt
// if the response wouldn't fit tx_buffer.
std::optional<size_t> build_a_record_response(uint16_t query_id, uint16_t query_flags,
                                               const uint8_t *question_section,
                                               size_t question_section_len,
                                               const std::array<uint8_t, 4> &ip,
                                               std::array<uint8_t, RX_BUFFER_SIZE> &tx_buffer)
{
    const size_t total_len = DNS_HEADER_SIZE + question_section_len + DNS_ANSWER_RR_SIZE;
    if (total_len > tx_buffer.size()) {
        return std::nullopt;
    }

    write_dns_response_header(tx_buffer.data(), query_id, query_flags, /*ancount=*/1,
                               DNS_RCODE_NOERROR);
    std::memcpy(tx_buffer.data() + DNS_HEADER_SIZE, question_section, question_section_len);

    size_t offset = DNS_HEADER_SIZE + question_section_len;
    write_uint16_be(tx_buffer.data(), offset, DNS_NAME_COMPRESSION_POINTER);
    offset += 2;
    write_uint16_be(tx_buffer.data(), offset, DNS_TYPE_A);
    offset += 2;
    write_uint16_be(tx_buffer.data(), offset, DNS_CLASS_IN);
    offset += 2;
    write_uint32_be(tx_buffer.data(), offset, ANSWER_TTL_SECONDS);
    offset += 4;
    write_uint16_be(tx_buffer.data(), offset, static_cast<uint16_t>(ip.size()));
    offset += 2;
    std::memcpy(tx_buffer.data() + offset, ip.data(), ip.size());
    offset += ip.size();

    return offset;
}

// Builds an authoritative NXDOMAIN response echoing the request's question
// section, with no answer RR. The question is still echoed even on this
// error response: real resolvers match replies to pending queries by
// name/type/class as well as ID, so omitting it risks the reply being
// silently discarded by a strict client.
std::optional<size_t> build_nxdomain_response(uint16_t query_id, uint16_t query_flags,
                                               const uint8_t *question_section,
                                               size_t question_section_len,
                                               std::array<uint8_t, RX_BUFFER_SIZE> &tx_buffer)
{
    const size_t total_len = DNS_HEADER_SIZE + question_section_len;
    if (total_len > tx_buffer.size()) {
        return std::nullopt;
    }

    write_dns_response_header(tx_buffer.data(), query_id, query_flags, /*ancount=*/0,
                               DNS_RCODE_NXDOMAIN);
    std::memcpy(tx_buffer.data() + DNS_HEADER_SIZE, question_section, question_section_len);

    return total_len;
}

void dns_server_task(void *)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        vTaskDelete(nullptr);
        return;
    }

    sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_port = htons(DNS_PORT);

    if (bind(sock, reinterpret_cast<sockaddr *>(&dest_addr), sizeof(dest_addr)) < 0) {
        ESP_LOGE(TAG, "bind() to port %d failed: errno %d", DNS_PORT, errno);
        close(sock);
        vTaskDelete(nullptr);
        return;
    }
    ESP_LOGI(TAG, "listening on UDP port %d", DNS_PORT);

    std::array<uint8_t, RX_BUFFER_SIZE> rx_buffer;
    std::array<uint8_t, RX_BUFFER_SIZE> tx_buffer;

    while (true) {
        sockaddr_in source_addr = {};
        socklen_t socklen = sizeof(source_addr);

        int len = recvfrom(sock, rx_buffer.data(), rx_buffer.size(), 0,
                            reinterpret_cast<sockaddr *>(&source_addr), &socklen);
        if (len < 0) {
            ESP_LOGE(TAG, "recvfrom() failed: errno %d", errno);
            continue;
        }

        char addr_str[16];
        inet_ntoa_r(source_addr.sin_addr, addr_str, sizeof(addr_str));
        ESP_LOGI(TAG, "received %d bytes from %s:%d", len, addr_str,
                 ntohs(source_addr.sin_port));
        ESP_LOG_BUFFER_HEXDUMP(TAG, rx_buffer.data(), len, ESP_LOG_DEBUG);

        auto header = parse_dns_header(rx_buffer.data(), len);
        if (!header) {
            ESP_LOGW(TAG, "packet too short for a DNS header (%d bytes), dropping", len);
            continue;
        }

        if (header->qdcount == 0) {
            ESP_LOGW(TAG, "query id=%u has no question section, dropping",
                     static_cast<unsigned>(header->id));
            continue;
        }

        size_t offset = DNS_HEADER_SIZE;
        auto qname = parse_question_name(rx_buffer.data(), len, offset);
        if (!qname) {
            ESP_LOGW(TAG, "malformed/unsupported question name (id=%u), dropping",
                     static_cast<unsigned>(header->id));
            continue;
        }

        uint16_t qtype = 0;
        uint16_t qclass = 0;
        size_t question_section_end = offset;
        bool has_full_question = (offset + 4 <= static_cast<size_t>(len));
        if (has_full_question) {
            qtype = read_uint16_be(rx_buffer.data(), offset);
            qclass = read_uint16_be(rx_buffer.data(), offset + 2);
            question_section_end = offset + 4;
        }
        (void)qclass;

        ESP_LOGI(TAG, "query for '%s' type=%s(%u) id=%u qdcount=%u",
                 qname->empty() ? "." : qname->c_str(), qtype_to_string(qtype),
                 static_cast<unsigned>(qtype), static_cast<unsigned>(header->id),
                 static_cast<unsigned>(header->qdcount));

        if (!has_full_question) {
            ESP_LOGW(TAG, "truncated question (missing qtype/qclass) for '%s' (id=%u), dropping",
                     qname->c_str(), static_cast<unsigned>(header->id));
            continue;
        }

        const dns_record_t *record = find_dns_record(*qname);
        std::optional<size_t> response_len;
        if (record != nullptr && qtype == DNS_TYPE_A) {
            response_len = build_a_record_response(
                header->id, header->flags, rx_buffer.data() + DNS_HEADER_SIZE,
                question_section_end - DNS_HEADER_SIZE, record->ip, tx_buffer);
        } else {
            response_len = build_nxdomain_response(
                header->id, header->flags, rx_buffer.data() + DNS_HEADER_SIZE,
                question_section_end - DNS_HEADER_SIZE, tx_buffer);
        }

        if (!response_len) {
            ESP_LOGW(TAG, "failed to build response for '%s' (question too large), dropping",
                     qname->c_str());
            continue;
        }

        int sent = sendto(sock, tx_buffer.data(), *response_len, 0,
                           reinterpret_cast<sockaddr *>(&source_addr), socklen);
        if (sent < 0) {
            ESP_LOGE(TAG, "sendto() failed: errno %d", errno);
        } else if (record != nullptr && qtype == DNS_TYPE_A) {
            ESP_LOGI(TAG, "sent A record for '%s' (%d bytes) to %s:%d", qname->c_str(), sent,
                     addr_str, ntohs(source_addr.sin_port));
        } else {
            ESP_LOGI(TAG, "sent NXDOMAIN for '%s' (%d bytes) to %s:%d", qname->c_str(), sent,
                     addr_str, ntohs(source_addr.sin_port));
        }
    }
}

} // namespace

void dns_server_start()
{
    xTaskCreate(dns_server_task, "dns_server", 4096, nullptr, 5, nullptr);
}
