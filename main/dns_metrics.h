#pragma once

#include <array>
#include <atomic>
#include <cstdint>

// Runtime counters for the /metrics endpoint (see http_server.cpp and
// docs/superpowers/specs/2026-07-21-edge-dns-phase3-metrics-design.md).
// Written by the DNS task (dns_server.cpp/dns_forwarder.cpp), read by the
// HTTP task's metrics_get_handler — the same cross-task shape as
// DnsBlocklist's blocks_total_ (see dns_blocklist.h): no mutex, every
// field is a fixed-width atomic updated with memory_order_relaxed.
//
// uint32_t rather than uint64_t deliberately: this target's Xtensa LX7
// core has no native 64-bit atomic instructions, so std::atomic<uint64_t>
// would pull in libatomic's lock-based fallback and break the "no locks
// between tasks" property every other piece of shared state here relies
// on. A 32-bit counter wrapping after ~4B events is fine for a LAN-scale
// device scraped by Prometheus, which already tolerates counter resets.

// Upstream latency histogram bucket upper bounds, in milliseconds. The
// implicit final bucket is +Inf, giving BUCKET_COUNT total buckets.
constexpr std::array<uint32_t, 5> DNS_METRICS_LATENCY_BUCKETS_MS = {10, 50, 100, 500, 1000};
constexpr size_t DNS_METRICS_LATENCY_BUCKET_COUNT = DNS_METRICS_LATENCY_BUCKETS_MS.size() + 1;

// Point-in-time read of every counter/gauge, taken with one atomic load
// per field — not a single atomic snapshot of the whole struct, so two
// fields read a moment apart could in principle disagree by one event.
// That's an acceptable trade for a Prometheus scrape target: rate()
// smooths across scrapes anyway, and avoiding a lock keeps the writer
// side (the DNS task's hot path) mutex-free.
struct DnsMetricsSnapshot {
    uint32_t queries = 0;
    uint32_t local_hits = 0;
    uint32_t cache_hits = 0;
    uint32_t cache_misses = 0;
    uint32_t forwarded = 0;
    uint32_t upstream_replies = 0;
    uint32_t upstream_timeouts = 0;
    uint32_t upstream_retries = 0;
    uint32_t servfail = 0;
    std::array<uint32_t, DNS_METRICS_LATENCY_BUCKET_COUNT> latency_buckets{};
    uint64_t latency_sum_ms = 0;
    uint32_t latency_count = 0;
    uint32_t cache_entries = 0;
    uint32_t inflight = 0;
};

class DnsMetrics {
public:
    void inc_queries();
    void inc_local_hits();
    void inc_cache_hits();
    void inc_cache_misses();
    void inc_forwarded();
    void inc_upstream_replies();
    void inc_upstream_timeouts();
    // Bumped once per slot retried against the secondary upstream after
    // the primary's attempt timed out (Phase 6) — distinct from
    // upstream_timeouts, which now only counts *final* give-ups (the
    // secondary attempt also timing out), not the first-attempt timeout
    // that triggered the retry.
    void inc_upstream_retries();
    void inc_servfail();

    // Records one upstream round-trip time into the latency histogram:
    // bumps the first bucket whose upper bound is >= latency_ms (or the
    // +Inf bucket if it exceeds all of them), plus the running sum/count
    // Prometheus needs to derive an average alongside the distribution.
    void observe_upstream_latency(uint32_t latency_ms);

    // Gauges: republished from the DNS task's select() loop every
    // iteration (see dns_server.cpp) rather than incremented/decremented,
    // since the underlying counts (cache.size(), in-flight occupancy) are
    // already tracked by their owning classes.
    void set_cache_entries(uint32_t n);
    void set_inflight(uint32_t n);

    DnsMetricsSnapshot snapshot() const;

private:
    std::atomic<uint32_t> queries_{0};
    std::atomic<uint32_t> local_hits_{0};
    std::atomic<uint32_t> cache_hits_{0};
    std::atomic<uint32_t> cache_misses_{0};
    std::atomic<uint32_t> forwarded_{0};
    std::atomic<uint32_t> upstream_replies_{0};
    std::atomic<uint32_t> upstream_timeouts_{0};
    std::atomic<uint32_t> upstream_retries_{0};
    std::atomic<uint32_t> servfail_{0};

    std::array<std::atomic<uint32_t>, DNS_METRICS_LATENCY_BUCKET_COUNT> latency_buckets_{};
    std::atomic<uint64_t> latency_sum_ms_{0};
    std::atomic<uint32_t> latency_count_{0};

    std::atomic<uint32_t> cache_entries_{0};
    std::atomic<uint32_t> inflight_{0};
};

// Process-wide instance: the DNS task's various inc_*()/observe_*()/set_*()
// calls are the only writers; the HTTP task's metrics_get_handler is the
// only reader, via snapshot().
DnsMetrics &metrics();
