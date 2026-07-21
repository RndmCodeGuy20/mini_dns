#include "dns_server.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <optional>
#include <string>

#include "dns_blocklist.h"
#include "dns_cache.h"
#include "dns_forwarder.h"
#include "dns_metrics.h"
#include "dns_records.h"
#include "dns_wire.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

namespace {

constexpr const char *TAG = "dns_server";
constexpr uint16_t DNS_PORT = 53;
constexpr size_t RX_BUFFER_SIZE = 512;
constexpr size_t TX_BUFFER_SIZE = 512;

// Upper bound on how long select() blocks with nothing else scheduling
// a wakeup — also throttles how often the cache gets swept for expired
// entries (see the main loop). A pending forwarder deadline can still
// cut this shorter (see next_deadline_ms()).
constexpr int64_t SELECT_MAX_TIMEOUT_MS = 5000;

int64_t now_ms()
{
    return esp_timer_get_time() / 1000;
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

void send_response(int sock, const uint8_t *buf, size_t len, const sockaddr_in &to_addr,
                    socklen_t to_addr_len, const char *qname_for_log)
{
    int sent = sendto(sock, buf, len, 0, reinterpret_cast<const sockaddr *>(&to_addr), to_addr_len);
    if (sent < 0) {
        ESP_LOGE(TAG, "sendto() failed for '%s': errno %d", qname_for_log, errno);
    }
}

// Sends a SERVFAIL echoing the client's original question — used both
// when forwarding can't even be attempted (table full, send failure)
// and when an in-flight query times out with no upstream reply.
void send_servfail(int sock, const DnsForwarder::client_context_t &client)
{
    uint8_t tx_buffer[TX_BUFFER_SIZE];
    auto resp_len = build_relayed_response(
        client.client_txn_id, client.client_query_flags, client.question_section.data(),
        client.question_section.size(), DNS_RCODE_SERVFAIL, /*ancount=*/0,
        /*answer_section=*/nullptr, /*answer_section_len=*/0, tx_buffer, sizeof(tx_buffer));
    if (!resp_len) {
        ESP_LOGW(TAG, "SERVFAIL response too large to build, dropping");
        return;
    }
    send_response(sock, tx_buffer, *resp_len, client.client_addr, client.client_addr_len,
                  "(servfail)");
}

// Handles one reply that arrived on the forwarder's upstream socket:
// caches it and relays it to the original client.
void handle_upstream_reply(int listen_sock, DnsForwarder &forwarder, DnsCache &cache)
{
    auto reply = forwarder.handle_upstream_readable(now_ms());
    if (!reply) {
        return; // already logged by the forwarder
    }

    metrics().inc_upstream_replies();
    metrics().observe_upstream_latency(reply->latency_ms);

    uint32_t cache_ttl = reply->ancount > 0 ? reply->ttl_seconds : DNS_NEGATIVE_CACHE_TTL_SECONDS;
    cache.insert(reply->qname_lower, reply->qtype, reply->rcode, reply->ancount,
                 reply->answer_section, cache_ttl, now_ms());

    uint8_t tx_buffer[TX_BUFFER_SIZE];
    auto resp_len = build_relayed_response(
        reply->client.client_txn_id, reply->client.client_query_flags,
        reply->client.question_section.data(), reply->client.question_section.size(),
        reply->rcode, reply->ancount, reply->answer_section.data(), reply->answer_section.size(),
        tx_buffer, sizeof(tx_buffer));
    if (!resp_len) {
        ESP_LOGW(TAG, "relayed response too large to build for '%s', dropping",
                 reply->qname_lower.c_str());
        return;
    }
    send_response(listen_sock, tx_buffer, *resp_len, reply->client.client_addr,
                  reply->client.client_addr_len, reply->qname_lower.c_str());
}

// Handles one query that arrived on the listen socket: local table, then
// blocklist, then cache, then forwarding — see the design doc for why
// local records take precedence over anything cached/forwarded, and why
// the blocklist runs before the cache/forwarder (a cached or freshly
// forwarded answer for a blocked name would otherwise defeat the block).
void handle_client_query(int listen_sock, DnsForwarder &forwarder, DnsCache &cache)
{
    std::array<uint8_t, RX_BUFFER_SIZE> rx_buffer;
    sockaddr_in source_addr = {};
    socklen_t socklen = sizeof(source_addr);

    int len = recvfrom(listen_sock, rx_buffer.data(), rx_buffer.size(), 0,
                        reinterpret_cast<sockaddr *>(&source_addr), &socklen);
    if (len < 0) {
        ESP_LOGE(TAG, "recvfrom() failed: errno %d", errno);
        return;
    }

    char addr_str[16];
    inet_ntoa_r(source_addr.sin_addr, addr_str, sizeof(addr_str));
    ESP_LOGD(TAG, "received %d bytes from %s:%d", len, addr_str, ntohs(source_addr.sin_port));

    auto header = parse_dns_header(rx_buffer.data(), len);
    if (!header) {
        ESP_LOGW(TAG, "packet too short for a DNS header (%d bytes), dropping", len);
        return;
    }
    if (header->qdcount == 0) {
        ESP_LOGW(TAG, "query id=%u has no question section, dropping",
                 static_cast<unsigned>(header->id));
        return;
    }

    size_t offset = DNS_HEADER_SIZE;
    auto qname = parse_question_name(rx_buffer.data(), len, offset);
    if (!qname) {
        ESP_LOGW(TAG, "malformed/unsupported question name (id=%u), dropping",
                 static_cast<unsigned>(header->id));
        return;
    }

    bool has_full_question = (offset + 4 <= static_cast<size_t>(len));
    if (!has_full_question) {
        ESP_LOGW(TAG, "truncated question (missing qtype/qclass) for '%s' (id=%u), dropping",
                 qname->c_str(), static_cast<unsigned>(header->id));
        return;
    }
    uint16_t qtype = read_uint16_be(rx_buffer.data(), offset);
    size_t question_section_end = offset + 4;
    const uint8_t *question_section = rx_buffer.data() + DNS_HEADER_SIZE;
    size_t question_section_len = question_section_end - DNS_HEADER_SIZE;

    ESP_LOGI(TAG, "query for '%s' type=%s(%u) id=%u", qname->empty() ? "." : qname->c_str(),
             qtype_to_string(qtype), static_cast<unsigned>(qtype),
             static_cast<unsigned>(header->id));
    metrics().inc_queries();

    const dns_record_t *record = find_dns_record(*qname);
    uint8_t tx_buffer[TX_BUFFER_SIZE];

    if (record != nullptr) {
        metrics().inc_local_hits();
        // Local table is authoritative for this name regardless of
        // qtype — never shadowed by cache/upstream, preserving both the
        // "local always wins" property and the existing NXDOMAIN-for-
        // wrong-qtype simplification (see ARCHITECTURE.md).
        std::optional<size_t> resp_len;
        if (qtype == DNS_TYPE_A) {
            resp_len = build_a_record_response(header->id, header->flags, question_section,
                                                question_section_len, record->ip, tx_buffer,
                                                sizeof(tx_buffer));
        } else {
            resp_len = build_nxdomain_response(header->id, header->flags, question_section,
                                                question_section_len, tx_buffer, sizeof(tx_buffer));
        }
        if (resp_len) {
            send_response(listen_sock, tx_buffer, *resp_len, source_addr, socklen,
                          qname->c_str());
        }
        return;
    }

    std::string qname_lower = lowercase_ascii(*qname);

    if (blocklist().is_blocked(qname_lower)) {
        blocklist().record_block();
        std::optional<size_t> resp_len;
        if (qtype == DNS_TYPE_A) {
            constexpr std::array<uint8_t, 4> SINKHOLE_IP = {0, 0, 0, 0};
            resp_len = build_a_record_response(header->id, header->flags, question_section,
                                                question_section_len, SINKHOLE_IP, tx_buffer,
                                                sizeof(tx_buffer));
        } else {
            resp_len = build_nxdomain_response(header->id, header->flags, question_section,
                                                question_section_len, tx_buffer, sizeof(tx_buffer));
        }
        if (resp_len) {
            ESP_LOGI(TAG, "blocked '%s'", qname->c_str());
            send_response(listen_sock, tx_buffer, *resp_len, source_addr, socklen,
                          qname->c_str());
        }
        return;
    }

    const dns_cache_entry_t *cached = cache.lookup(qname_lower, qtype, now_ms());
    if (cached != nullptr) {
        metrics().inc_cache_hits();
        auto resp_len = build_relayed_response(header->id, header->flags, question_section,
                                                question_section_len, cached->rcode,
                                                cached->ancount, cached->answer_section.data(),
                                                cached->answer_section.size(), tx_buffer,
                                                sizeof(tx_buffer));
        if (resp_len) {
            ESP_LOGI(TAG, "cache hit for '%s'", qname->c_str());
            send_response(listen_sock, tx_buffer, *resp_len, source_addr, socklen,
                          qname->c_str());
        }
        return;
    }
    metrics().inc_cache_misses();

    bool forwarded = forwarder.forward(qname_lower, qtype, header->id, header->flags,
                                        question_section, question_section_len, source_addr,
                                        socklen, now_ms());
    if (forwarded) {
        metrics().inc_forwarded();
    } else {
        metrics().inc_servfail();
        send_servfail(listen_sock,
                      {header->id, header->flags,
                       std::vector<uint8_t>(question_section,
                                             question_section + question_section_len),
                       source_addr, socklen});
    }
}

void dns_server_task(void *)
{
    int listen_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        vTaskDelete(nullptr);
        return;
    }

    sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_port = htons(DNS_PORT);

    if (bind(listen_sock, reinterpret_cast<sockaddr *>(&dest_addr), sizeof(dest_addr)) < 0) {
        ESP_LOGE(TAG, "bind() to port %d failed: errno %d", DNS_PORT, errno);
        close(listen_sock);
        vTaskDelete(nullptr);
        return;
    }
    ESP_LOGI(TAG, "listening on UDP port %d", DNS_PORT);

    // A forwarder that fails to start runs in a permanently-degraded
    // mode (local table only, everything else NXDOMAIN) rather than
    // aborting the device — see DnsForwarder::start()'s doc comment.
    static DnsForwarder forwarder;
    static DnsCache cache;
    bool forwarding_enabled = forwarder.start();
    if (!forwarding_enabled) {
        ESP_LOGW(TAG, "forwarding unavailable; serving local table only");
    }

    while (true) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        int max_fd = listen_sock;
        if (forwarding_enabled) {
            FD_SET(forwarder.socket_fd(), &read_fds);
            max_fd = std::max(max_fd, forwarder.socket_fd());
        }

        int64_t timeout_ms = SELECT_MAX_TIMEOUT_MS;
        if (forwarding_enabled) {
            int64_t deadline = forwarder.next_deadline_ms();
            if (deadline >= 0) {
                timeout_ms = std::max<int64_t>(0, std::min(timeout_ms, deadline - now_ms()));
            }
        }
        timeval tv = {};
        tv.tv_sec = static_cast<time_t>(timeout_ms / 1000);
        tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);

        int ready = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

        if (forwarding_enabled) {
            for (const auto &expired : forwarder.reap_expired(now_ms())) {
                ESP_LOGW(TAG, "upstream query timed out, sending SERVFAIL");
                metrics().inc_upstream_timeouts();
                metrics().inc_servfail();
                send_servfail(listen_sock, expired);
            }
        }

        if (ready < 0) {
            if (errno != EINTR) {
                ESP_LOGE(TAG, "select() failed: errno %d", errno);
            }
            continue;
        }
        if (ready == 0) {
            cache.sweep_expired(now_ms());
            continue;
        }

        if (forwarding_enabled && FD_ISSET(forwarder.socket_fd(), &read_fds)) {
            handle_upstream_reply(listen_sock, forwarder, cache);
        }
        if (FD_ISSET(listen_sock, &read_fds)) {
            handle_client_query(listen_sock, forwarder, cache);
        }

        // Republished every iteration rather than incrementally, since
        // cache/forwarder occupancy already lives in their own owning
        // classes — see DnsMetrics::set_cache_entries()/set_inflight().
        metrics().set_cache_entries(static_cast<uint32_t>(cache.size()));
        if (forwarding_enabled) {
            metrics().set_inflight(static_cast<uint32_t>(forwarder.in_flight_count()));
        }
    }
}

} // namespace

void dns_server_start()
{
    // Loaded synchronously, before the task (and before http_server_start(),
    // called after this returns — see main.cpp) — so neither the first
    // query nor the first /api/blocklist request can race an empty list.
    esp_err_t blocklist_err = blocklist().load_from_nvs();
    if (blocklist_err != ESP_OK) {
        ESP_LOGW(TAG, "blocklist failed to load (%s); starting with an empty list",
                 esp_err_to_name(blocklist_err));
    }

    xTaskCreate(dns_server_task, "dns_server", 6144, nullptr, 5, nullptr);
}
