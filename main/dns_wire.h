#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

// Pure DNS wire-format helpers: no sockets, no I/O, no global state. Every
// function here operates only on byte buffers passed in, which is what
// makes them the natural candidates for host-side unit tests (see
// ARCHITECTURE.md's "No automated tests" gotcha) — extracted from
// dns_server.cpp so that testability doesn't require pulling in FreeRTOS/
// lwIP headers.

constexpr size_t DNS_HEADER_SIZE = 12;
constexpr size_t DNS_QNAME_MAX_LENGTH = 255;
constexpr uint16_t DNS_TYPE_A = 1;
constexpr uint16_t DNS_TYPE_AAAA = 28;
constexpr uint16_t DNS_CLASS_IN = 1;
constexpr uint16_t DNS_NAME_COMPRESSION_POINTER = 0xC00C; // pointer to offset 12 (question name)
constexpr size_t DNS_ANSWER_RR_FIXED_SIZE = 10; // type(2)+class(2)+ttl(4)+rdlength(2), before rdata
constexpr uint16_t DNS_RCODE_NOERROR = 0;
constexpr uint16_t DNS_RCODE_SERVFAIL = 2;
constexpr uint16_t DNS_RCODE_NXDOMAIN = 3;

struct dns_header_t {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

uint16_t read_uint16_be(const uint8_t *buf, size_t offset);
uint32_t read_uint32_be(const uint8_t *buf, size_t offset);
void write_uint16_be(uint8_t *buf, size_t offset, uint16_t value);
void write_uint32_be(uint8_t *buf, size_t offset, uint32_t value);

std::optional<dns_header_t> parse_dns_header(const uint8_t *buf, size_t len);

// Walks the length-prefixed labels of a question-section QNAME starting at
// `offset`, advancing it past the terminating zero-length label. Name
// compression pointers are rejected rather than followed: real queries never
// use them in the question section, and doing so would let untrusted length
// bytes drive further reads into unrelated buffer regions.
std::optional<std::string> parse_question_name(const uint8_t *buf, size_t len, size_t &offset);

// Advances `offset` past one encoded name, for contexts (answer/authority/
// additional RRs) where compression pointers are the normal case rather
// than a rejected one. Unlike parse_question_name, this doesn't build the
// name string or follow the pointer to resolve it — it only needs to know
// how many bytes the name occupies here, since a pointer always terminates
// the name in place (RFC 1035 §4.1.4). Returns false on malformed input.
bool skip_name(const uint8_t *buf, size_t len, size_t &offset);

// Result of scanning an RR section (see scan_answer_section): where the
// section ends, and the minimum TTL across its RRs — the bound a cache
// entry built from this section may be trusted for.
struct answer_section_scan_t {
    size_t end_offset;
    uint32_t min_ttl;
};

// Walks `ancount` resource records starting at `answer_start_offset`
// (immediately after the question section), using skip_name to handle
// each RR's (usually compressed) name, then reading the fixed
// type/class/ttl/rdlength fields and skipping rdata. Used both to bound
// a cache entry's freshness and to find where the answer section ends
// (authority/additional sections, if any, are intentionally not
// followed into or cached — see dns_cache.h). ancount == 0 is valid and
// returns end_offset == answer_start_offset with min_ttl == 0.
std::optional<answer_section_scan_t> scan_answer_section(const uint8_t *buf, size_t len,
                                                          size_t answer_start_offset,
                                                          uint16_t ancount);

const char *qtype_to_string(uint16_t qtype);

// Builds a DNS response echoing the request's question section verbatim,
// followed by a single A-record answer that uses a compression pointer
// back to the question name (always at offset 12, since the question is
// always the first thing written after the header). Returns std::nullopt
// if the response wouldn't fit in tx_capacity bytes.
std::optional<size_t> build_a_record_response(uint16_t query_id, uint16_t query_flags,
                                               const uint8_t *question_section,
                                               size_t question_section_len,
                                               const std::array<uint8_t, 4> &ip,
                                               uint8_t *tx_buffer, size_t tx_capacity);

// Same as build_a_record_response, but for a single AAAA (rtype 28) answer
// with 16-byte rdata. Shares the same compression-pointer-to-question-name
// layout — see build_a_record_response's comment.
std::optional<size_t> build_aaaa_record_response(uint16_t query_id, uint16_t query_flags,
                                                  const uint8_t *question_section,
                                                  size_t question_section_len,
                                                  const std::array<uint8_t, 16> &ip,
                                                  uint8_t *tx_buffer, size_t tx_capacity);

// Builds an authoritative NXDOMAIN response echoing the request's question
// section, with no answer RR. The question is still echoed even on this
// error response: real resolvers match replies to pending queries by
// name/type/class as well as ID, so omitting it risks the reply being
// silently discarded by a strict client.
std::optional<size_t> build_nxdomain_response(uint16_t query_id, uint16_t query_flags,
                                               const uint8_t *question_section,
                                               size_t question_section_len,
                                               uint8_t *tx_buffer, size_t tx_capacity);

// Builds a NOERROR response with zero answers ("NODATA" in common usage,
// RFC 2308 §2.2): the name exists, but not for the queried type. Distinct
// from NXDOMAIN (the name doesn't exist at all) — see the dual-stack
// resolution path in dns_server.cpp for why this matters once a local
// name can hold an A, an AAAA, or both: querying the absent family must
// not tell a dual-stack client the name doesn't exist.
std::optional<size_t> build_nodata_response(uint16_t query_id, uint16_t query_flags,
                                             const uint8_t *question_section,
                                             size_t question_section_len, uint8_t *tx_buffer,
                                             size_t tx_capacity);

// Builds a response by relaying a previously-captured answer section
// (see dns_cache.h) behind a fresh header/question: used for both cache
// hits and forwarded-upstream replies. `answer_section` is RR bytes only
// (as produced by scan_answer_section's end_offset), with no authority/
// additional data. `rcode` and `ancount` come from the original upstream
// reply (or SERVFAIL/0 if none). Any compression pointers inside
// `answer_section` remain valid because it's placed at the same absolute
// offset (DNS_HEADER_SIZE + question_section_len) as when it was captured
// — see dns_cache.h's caching contract for why that invariant holds.
std::optional<size_t> build_relayed_response(uint16_t query_id, uint16_t query_flags,
                                              const uint8_t *question_section,
                                              size_t question_section_len, uint16_t rcode,
                                              uint16_t ancount, const uint8_t *answer_section,
                                              size_t answer_section_len, uint8_t *tx_buffer,
                                              size_t tx_capacity);
