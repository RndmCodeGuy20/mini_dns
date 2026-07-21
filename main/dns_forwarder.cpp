#include "dns_forwarder.h"

#include <cerrno>
#include <cstring>

#include "dns_wire.h"
#include "esp_log.h"

namespace {
constexpr const char *TAG = "dns_forwarder";
constexpr size_t UPSTREAM_RX_BUFFER_SIZE = 512; // matches dns_server.cpp's RX_BUFFER_SIZE
constexpr size_t UPSTREAM_TX_BUFFER_SIZE = 512;

// Slot index occupies the low bits of the 16-bit upstream transaction
// ID; the remaining high bits are a per-slot generation counter. A
// generation mismatch on an incoming reply means it's stale (arrived
// after its slot was reaped and reused, or was a spoofed/duplicate
// packet) — this is what lets slot index alone give O(1) matching while
// still safely rejecting replies that only coincidentally share an
// index. DNS_FORWARDER_MAX_IN_FLIGHT must be a power of two for the
// masking below to partition the 16 bits cleanly.
static_assert((DNS_FORWARDER_MAX_IN_FLIGHT & (DNS_FORWARDER_MAX_IN_FLIGHT - 1)) == 0,
              "DNS_FORWARDER_MAX_IN_FLIGHT must be a power of two");
constexpr uint16_t SLOT_INDEX_BITS = [] {
    uint16_t bits = 0;
    for (size_t n = DNS_FORWARDER_MAX_IN_FLIGHT; n > 1; n >>= 1) {
        ++bits;
    }
    return bits;
}();
constexpr uint16_t SLOT_INDEX_MASK = static_cast<uint16_t>(DNS_FORWARDER_MAX_IN_FLIGHT - 1);
constexpr uint16_t GENERATION_MASK = static_cast<uint16_t>(~SLOT_INDEX_MASK);

uint16_t make_upstream_txn_id(size_t slot_index, uint16_t generation)
{
    return static_cast<uint16_t>((generation << SLOT_INDEX_BITS) |
                                  (slot_index & SLOT_INDEX_MASK));
}
} // namespace

DnsForwarder::DnsForwarder(const char *upstream_ip, uint16_t upstream_port, int64_t timeout_ms)
    : timeout_ms_(timeout_ms)
{
    upstream_addr_.sin_family = AF_INET;
    upstream_addr_.sin_port = htons(upstream_port);
    upstream_addr_.sin_addr.s_addr = inet_addr(upstream_ip);
}

bool DnsForwarder::start()
{
    sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock_ < 0) {
        ESP_LOGE(TAG, "socket() for upstream forwarding failed: errno %d — forwarding disabled",
                 errno);
        return false;
    }
    ESP_LOGI(TAG, "forwarding to upstream %s:%d", DNS_FORWARDER_UPSTREAM_IP,
             ntohs(upstream_addr_.sin_port));
    return true;
}

int DnsForwarder::find_free_slot() const
{
    for (size_t i = 0; i < slots_.size(); ++i) {
        if (!slots_[i].occupied) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool DnsForwarder::forward(const std::string &qname_lower, uint16_t qtype,
                           uint16_t client_txn_id, uint16_t client_query_flags,
                           const uint8_t *question_section, size_t question_section_len,
                           const sockaddr_in &client_addr, socklen_t client_addr_len,
                           int64_t now_ms)
{
    if (sock_ < 0) {
        return false; // forwarding unavailable (start() failed)
    }
    if (DNS_HEADER_SIZE + question_section_len > UPSTREAM_TX_BUFFER_SIZE) {
        ESP_LOGW(TAG, "question too large to forward (%zu bytes), dropping",
                 question_section_len);
        return false;
    }

    int index = find_free_slot();
    if (index < 0) {
        ESP_LOGW(TAG, "in-flight table full (%zu slots), dropping '%s'",
                 slots_.size(), qname_lower.c_str());
        return false;
    }

    in_flight_slot_t &slot = slots_[static_cast<size_t>(index)];
    slot.generation = static_cast<uint16_t>((slot.generation + 1) & (GENERATION_MASK >> SLOT_INDEX_BITS));
    slot.client_txn_id = client_txn_id;
    slot.client_query_flags = client_query_flags;
    slot.qtype = qtype;
    slot.qname_lower = qname_lower;
    slot.question_section.assign(question_section, question_section + question_section_len);
    slot.client_addr = client_addr;
    slot.client_addr_len = client_addr_len;
    slot.deadline_ms = now_ms + timeout_ms_;

    uint16_t upstream_txn_id = make_upstream_txn_id(static_cast<size_t>(index), slot.generation);

    uint8_t query_buf[UPSTREAM_TX_BUFFER_SIZE];
    write_uint16_be(query_buf, 0, upstream_txn_id);
    write_uint16_be(query_buf, 2, 0x0100); // standard query, RD=1
    write_uint16_be(query_buf, 4, 1);      // QDCOUNT
    write_uint16_be(query_buf, 6, 0);
    write_uint16_be(query_buf, 8, 0);
    write_uint16_be(query_buf, 10, 0);
    std::memcpy(query_buf + DNS_HEADER_SIZE, question_section, question_section_len);

    size_t query_len = DNS_HEADER_SIZE + question_section_len;
    int sent = sendto(sock_, query_buf, query_len, 0,
                       reinterpret_cast<const sockaddr *>(&upstream_addr_),
                       sizeof(upstream_addr_));
    if (sent < 0) {
        ESP_LOGE(TAG, "sendto(upstream) failed: errno %d", errno);
        slot.occupied = false;
        return false;
    }

    slot.occupied = true;
    return true;
}

std::optional<DnsForwarder::reply_t> DnsForwarder::handle_upstream_readable(int64_t now_ms)
{
    uint8_t rx_buffer[UPSTREAM_RX_BUFFER_SIZE];
    sockaddr_in from_addr = {};
    socklen_t from_len = sizeof(from_addr);

    int len = recvfrom(sock_, rx_buffer, sizeof(rx_buffer), 0,
                        reinterpret_cast<sockaddr *>(&from_addr), &from_len);
    if (len < 0) {
        ESP_LOGE(TAG, "recvfrom(upstream) failed: errno %d", errno);
        return std::nullopt;
    }

    if (from_addr.sin_addr.s_addr != upstream_addr_.sin_addr.s_addr ||
        from_addr.sin_port != upstream_addr_.sin_port) {
        ESP_LOGW(TAG, "reply from unexpected source, dropping");
        return std::nullopt;
    }

    auto header = parse_dns_header(rx_buffer, static_cast<size_t>(len));
    if (!header || header->qdcount == 0) {
        ESP_LOGW(TAG, "malformed upstream reply, dropping");
        return std::nullopt;
    }

    size_t slot_index = header->id & SLOT_INDEX_MASK;
    uint16_t generation = static_cast<uint16_t>(header->id >> SLOT_INDEX_BITS);
    in_flight_slot_t &slot = slots_[slot_index];

    if (!slot.occupied || slot.generation != generation) {
        ESP_LOGW(TAG, "reply id=%u doesn't match any in-flight query (stale/spoofed?), dropping",
                 static_cast<unsigned>(header->id));
        return std::nullopt;
    }

    size_t offset = DNS_HEADER_SIZE;
    auto qname = parse_question_name(rx_buffer, static_cast<size_t>(len), offset);
    if (!qname || offset + 4 > static_cast<size_t>(len)) {
        ESP_LOGW(TAG, "malformed question in upstream reply for '%s', dropping",
                 slot.qname_lower.c_str());
        slot.occupied = false;
        return std::nullopt;
    }
    size_t question_section_end = offset + 4; // qtype + qclass

    auto scan = scan_answer_section(rx_buffer, static_cast<size_t>(len), question_section_end,
                                     header->ancount);
    if (!scan) {
        ESP_LOGW(TAG, "malformed answer section in upstream reply for '%s', dropping",
                 slot.qname_lower.c_str());
        slot.occupied = false;
        return std::nullopt;
    }

    reply_t reply;
    reply.client = {slot.client_txn_id, slot.client_query_flags, std::move(slot.question_section),
                    slot.client_addr, slot.client_addr_len};
    reply.qname_lower = slot.qname_lower;
    reply.qtype = slot.qtype;
    reply.rcode = header->flags & 0x000F;
    reply.ancount = header->ancount;
    reply.answer_section.assign(rx_buffer + question_section_end, rx_buffer + scan->end_offset);
    reply.ttl_seconds = scan->min_ttl;

    slot.occupied = false;
    return reply;
}

std::vector<DnsForwarder::client_context_t> DnsForwarder::reap_expired(int64_t now_ms)
{
    std::vector<client_context_t> expired;
    for (auto &slot : slots_) {
        if (slot.occupied && slot.deadline_ms <= now_ms) {
            expired.push_back({slot.client_txn_id, slot.client_query_flags,
                                std::move(slot.question_section), slot.client_addr,
                                slot.client_addr_len});
            slot.occupied = false;
        }
    }
    return expired;
}

int64_t DnsForwarder::next_deadline_ms() const
{
    int64_t soonest = -1;
    for (const auto &slot : slots_) {
        if (slot.occupied && (soonest < 0 || slot.deadline_ms < soonest)) {
            soonest = slot.deadline_ms;
        }
    }
    return soonest;
}
