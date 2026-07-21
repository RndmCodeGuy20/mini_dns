#pragma once

// Starts the DNS UDP listener as its own FreeRTOS task. Binds to
// INADDR_ANY:53 and answers each query from, in order: the local static
// table (dns_records.h), the TTL cache (dns_cache.h), or by forwarding
// to an upstream resolver (dns_forwarder.h) and caching the result.
// Non-blocking: returns immediately after creating the task.
void dns_server_start();
