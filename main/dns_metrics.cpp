#include "dns_metrics.h"

void DnsMetrics::inc_queries()
{
    queries_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::inc_local_hits()
{
    local_hits_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::inc_cache_hits()
{
    cache_hits_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::inc_cache_misses()
{
    cache_misses_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::inc_forwarded()
{
    forwarded_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::inc_upstream_replies()
{
    upstream_replies_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::inc_upstream_timeouts()
{
    upstream_timeouts_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::inc_servfail()
{
    servfail_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::observe_upstream_latency(uint32_t latency_ms)
{
    size_t bucket = DNS_METRICS_LATENCY_BUCKETS_MS.size(); // default: +Inf
    for (size_t i = 0; i < DNS_METRICS_LATENCY_BUCKETS_MS.size(); ++i) {
        if (latency_ms <= DNS_METRICS_LATENCY_BUCKETS_MS[i]) {
            bucket = i;
            break;
        }
    }
    latency_buckets_[bucket].fetch_add(1, std::memory_order_relaxed);
    latency_sum_ms_.fetch_add(latency_ms, std::memory_order_relaxed);
    latency_count_.fetch_add(1, std::memory_order_relaxed);
}

void DnsMetrics::set_cache_entries(uint32_t n)
{
    cache_entries_.store(n, std::memory_order_relaxed);
}

void DnsMetrics::set_inflight(uint32_t n)
{
    inflight_.store(n, std::memory_order_relaxed);
}

DnsMetricsSnapshot DnsMetrics::snapshot() const
{
    DnsMetricsSnapshot s;
    s.queries = queries_.load(std::memory_order_relaxed);
    s.local_hits = local_hits_.load(std::memory_order_relaxed);
    s.cache_hits = cache_hits_.load(std::memory_order_relaxed);
    s.cache_misses = cache_misses_.load(std::memory_order_relaxed);
    s.forwarded = forwarded_.load(std::memory_order_relaxed);
    s.upstream_replies = upstream_replies_.load(std::memory_order_relaxed);
    s.upstream_timeouts = upstream_timeouts_.load(std::memory_order_relaxed);
    s.servfail = servfail_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < latency_buckets_.size(); ++i) {
        s.latency_buckets[i] = latency_buckets_[i].load(std::memory_order_relaxed);
    }
    s.latency_sum_ms = latency_sum_ms_.load(std::memory_order_relaxed);
    s.latency_count = latency_count_.load(std::memory_order_relaxed);
    s.cache_entries = cache_entries_.load(std::memory_order_relaxed);
    s.inflight = inflight_.load(std::memory_order_relaxed);
    return s;
}

DnsMetrics &metrics()
{
    static DnsMetrics instance;
    return instance;
}
