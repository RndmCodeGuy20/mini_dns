#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "lwip/sockets.h"

// Upstream DNS forwarding: owns the client UDP socket used to query an
// upstream recursive resolver, and the in-flight query table that
// correlates upstream replies back to the client that asked. Single-
// owner by design (see dns_cache.h) — every method is meant to be called
// only from the DNS task's select() loop in dns_server.cpp.
//
// This exists because a client query can't just be forwarded and waited
// on synchronously: that would stall every other client for the
// upstream's round-trip. Instead dns_server.cpp's select() loop treats
// the forwarder's socket as a second thing to wait on alongside the
// listen socket, and this table is what makes an arbitrarily-delayed or
// lost upstream reply resolvable back to (or safely timed out for) the
// original client — see docs/superpowers/specs/
// 2026-07-21-edge-dns-phase1-design.md for the full design rationale.

// Table size must be a power of two: it doubles as the low bits of the
// upstream transaction ID (see DnsForwarder's .cpp for the encoding).
constexpr size_t DNS_FORWARDER_MAX_IN_FLIGHT = 32;
constexpr int64_t DNS_FORWARDER_TIMEOUT_MS = 2000;
constexpr const char *DNS_FORWARDER_UPSTREAM_IP = "1.1.1.1";
constexpr uint16_t DNS_FORWARDER_UPSTREAM_PORT = 53;

class DnsForwarder {
public:
    DnsForwarder(const char *upstream_ip = DNS_FORWARDER_UPSTREAM_IP,
                 uint16_t upstream_port = DNS_FORWARDER_UPSTREAM_PORT,
                 int64_t timeout_ms = DNS_FORWARDER_TIMEOUT_MS);

    // Opens the upstream UDP client socket. Returns false on failure —
    // callers should treat this as a non-fatal degraded mode (local
    // table still works, forwarding silently unavailable) rather than
    // aborting the device: unlike httpd_start's "no meaningful degraded
    // mode exists" case, "no upstream reachable yet at boot" is an
    // ordinary, recoverable condition on a device that's also bringing
    // up its own network stack.
    bool start();

    int socket_fd() const { return sock_; }

    // Allocates an in-flight slot for this query and sends it upstream
    // as a fresh query with a device-assigned transaction ID. Returns
    // false if the table is full or the send failed — caller should
    // respond SERVFAIL to the client in that case.
    bool forward(const std::string &qname_lower, uint16_t qtype, uint16_t client_txn_id,
                 uint16_t client_query_flags, const uint8_t *question_section,
                 size_t question_section_len, const sockaddr_in &client_addr,
                 socklen_t client_addr_len, int64_t now_ms);

    // Everything needed to build and send the client-facing response
    // (or SERVFAIL, for timeout_t) for one resolved or expired in-flight
    // query.
    struct client_context_t {
        uint16_t client_txn_id;
        uint16_t client_query_flags;
        std::vector<uint8_t> question_section;
        sockaddr_in client_addr;
        socklen_t client_addr_len;
    };

    struct reply_t {
        client_context_t client;
        std::string qname_lower;
        uint16_t qtype;
        uint16_t rcode;
        uint16_t ancount;
        std::vector<uint8_t> answer_section; // RR bytes only; see scan_answer_section
        uint32_t ttl_seconds;                // meaningful only when ancount > 0
    };

    // Call when socket_fd() is readable: reads one upstream reply,
    // matches it to its in-flight slot, and returns the info needed to
    // respond to the client and cache the answer. Returns nullopt (and
    // logs why) on a reply that doesn't match any in-flight slot,
    // arrives from an unexpected source, or fails to parse — in all
    // those cases nothing further needs to happen (a genuine timeout is
    // handled separately by reap_expired).
    std::optional<reply_t> handle_upstream_readable(int64_t now_ms);

    // Frees and returns the client context for every in-flight slot
    // whose deadline has passed as of now_ms, so the caller can send
    // each one a SERVFAIL. Call once per select() loop iteration.
    std::vector<client_context_t> reap_expired(int64_t now_ms);

    // Soonest deadline among in-flight slots, or -1 if none are in
    // flight — lets the caller size select()'s timeout so an expiring
    // slot is reaped promptly rather than waiting on unrelated I/O.
    int64_t next_deadline_ms() const;

private:
    struct in_flight_slot_t {
        bool occupied = false;
        uint16_t generation = 0;
        uint16_t client_txn_id = 0;
        uint16_t client_query_flags = 0;
        uint16_t qtype = 0;
        std::string qname_lower;
        std::vector<uint8_t> question_section;
        sockaddr_in client_addr{};
        socklen_t client_addr_len = 0;
        int64_t deadline_ms = 0;
    };

    int sock_ = -1;
    sockaddr_in upstream_addr_{};
    int64_t timeout_ms_;
    std::array<in_flight_slot_t, DNS_FORWARDER_MAX_IN_FLIGHT> slots_{};

    int find_free_slot() const;
};
