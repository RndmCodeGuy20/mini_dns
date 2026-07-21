// Host-side unit tests for main/dns_wire.h/.cpp (Phase 6) — see
// ARCHITECTURE.md's "No automated tests" gotcha. dns_wire.cpp has no
// FreeRTOS/lwIP dependency, so these run on ESP-IDF's "linux" target with
// no hardware or QEMU involved:
//
//   idf.py --preview set-target linux -C host_test build
//   ./host_test/build/host_test.elf

#include <cstdlib>
#include <cstring>
#include <vector>

#include "dns_wire.h"
#include "unity.h"

namespace {

// Encodes a dotted name ("test.loc") as length-prefixed labels terminated
// by the zero-length root label — the on-wire form parse_question_name/
// skip_name expect. Empty string encodes just the root label (".").
std::vector<uint8_t> encode_name(const char *dotted)
{
    std::vector<uint8_t> out;
    const char *label_start = dotted;
    const char *p = dotted;
    while (true) {
        if (*p == '.' || *p == '\0') {
            size_t label_len = static_cast<size_t>(p - label_start);
            if (label_len > 0) {
                out.push_back(static_cast<uint8_t>(label_len));
                out.insert(out.end(), label_start, p);
            }
            if (*p == '\0') {
                break;
            }
            label_start = p + 1;
        }
        ++p;
    }
    out.push_back(0); // root label
    return out;
}

// Appends a 2-byte qtype and 2-byte qclass (IN) to a name, producing a full
// question section as build_*_response()/parse_question_name's callers use
// it (dns_server.cpp includes qtype/qclass in question_section_len).
std::vector<uint8_t> encode_question(const char *dotted, uint16_t qtype)
{
    std::vector<uint8_t> q = encode_name(dotted);
    q.push_back(static_cast<uint8_t>(qtype >> 8));
    q.push_back(static_cast<uint8_t>(qtype & 0xFF));
    q.push_back(0); // qclass IN, high byte
    q.push_back(static_cast<uint8_t>(DNS_CLASS_IN));
    return q;
}

} // namespace

// --- read/write_uint16/32_be ------------------------------------------

TEST_CASE("uint16_be round-trips", "[dns_wire]")
{
    uint8_t buf[2] = {};
    write_uint16_be(buf, 0, 0xBEEF);
    TEST_ASSERT_EQUAL_UINT8(0xBE, buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0xEF, buf[1]);
    TEST_ASSERT_EQUAL_UINT16(0xBEEF, read_uint16_be(buf, 0));
}

TEST_CASE("uint32_be round-trips", "[dns_wire]")
{
    uint8_t buf[4] = {};
    write_uint32_be(buf, 0, 0xDEADBEEF);
    TEST_ASSERT_EQUAL_UINT8(0xDE, buf[0]);
    TEST_ASSERT_EQUAL_UINT8(0xAD, buf[1]);
    TEST_ASSERT_EQUAL_UINT8(0xBE, buf[2]);
    TEST_ASSERT_EQUAL_UINT8(0xEF, buf[3]);
    TEST_ASSERT_EQUAL_UINT32(0xDEADBEEF, read_uint32_be(buf, 0));
}

// --- parse_dns_header ----------------------------------------------------

TEST_CASE("parse_dns_header rejects a too-short buffer", "[dns_wire]")
{
    uint8_t buf[DNS_HEADER_SIZE - 1] = {};
    TEST_ASSERT_FALSE(parse_dns_header(buf, sizeof(buf)).has_value());
}

TEST_CASE("parse_dns_header reads every field", "[dns_wire]")
{
    uint8_t buf[DNS_HEADER_SIZE] = {};
    write_uint16_be(buf, 0, 0x1234);  // id
    write_uint16_be(buf, 2, 0x8180);  // flags
    write_uint16_be(buf, 4, 1);       // qdcount
    write_uint16_be(buf, 6, 2);       // ancount
    write_uint16_be(buf, 8, 3);       // nscount
    write_uint16_be(buf, 10, 4);      // arcount

    auto header = parse_dns_header(buf, sizeof(buf));
    TEST_ASSERT_TRUE(header.has_value());
    TEST_ASSERT_EQUAL_UINT16(0x1234, header->id);
    TEST_ASSERT_EQUAL_UINT16(0x8180, header->flags);
    TEST_ASSERT_EQUAL_UINT16(1, header->qdcount);
    TEST_ASSERT_EQUAL_UINT16(2, header->ancount);
    TEST_ASSERT_EQUAL_UINT16(3, header->nscount);
    TEST_ASSERT_EQUAL_UINT16(4, header->arcount);
}

// --- parse_question_name --------------------------------------------------

TEST_CASE("parse_question_name decodes a multi-label name", "[dns_wire]")
{
    auto encoded = encode_name("test.loc");
    size_t offset = 0;
    auto name = parse_question_name(encoded.data(), encoded.size(), offset);
    TEST_ASSERT_TRUE(name.has_value());
    TEST_ASSERT_EQUAL_STRING("test.loc", name->c_str());
    TEST_ASSERT_EQUAL_size_t(encoded.size(), offset);
}

TEST_CASE("parse_question_name decodes the root name", "[dns_wire]")
{
    auto encoded = encode_name("");
    size_t offset = 0;
    auto name = parse_question_name(encoded.data(), encoded.size(), offset);
    TEST_ASSERT_TRUE(name.has_value());
    TEST_ASSERT_EQUAL_STRING("", name->c_str());
}

TEST_CASE("parse_question_name rejects a compression pointer", "[dns_wire]")
{
    uint8_t buf[2] = {0xC0, 0x0C}; // top two bits set = compression pointer
    size_t offset = 0;
    TEST_ASSERT_FALSE(parse_question_name(buf, sizeof(buf), offset).has_value());
}

TEST_CASE("parse_question_name rejects a truncated label", "[dns_wire]")
{
    uint8_t buf[] = {4, 't', 'e'}; // label claims 4 bytes, only 2 present
    size_t offset = 0;
    TEST_ASSERT_FALSE(parse_question_name(buf, sizeof(buf), offset).has_value());
}

TEST_CASE("parse_question_name rejects a name over 255 bytes", "[dns_wire]")
{
    // 5 labels of 63 bytes each: 5*63 + 4 dots = 319, well over
    // DNS_QNAME_MAX_LENGTH (255). (4 labels lands at exactly 255, which is
    // still valid — the check is "> 255", not ">=".)
    std::string label(63, 'a');
    std::string dotted = label + "." + label + "." + label + "." + label + "." + label;
    auto encoded = encode_name(dotted.c_str());
    size_t offset = 0;
    TEST_ASSERT_FALSE(parse_question_name(encoded.data(), encoded.size(), offset).has_value());
}

// --- skip_name -------------------------------------------------------------

TEST_CASE("skip_name advances past labels and the root label", "[dns_wire]")
{
    auto encoded = encode_name("nas.loc");
    size_t offset = 0;
    TEST_ASSERT_TRUE(skip_name(encoded.data(), encoded.size(), offset));
    TEST_ASSERT_EQUAL_size_t(encoded.size(), offset);
}

TEST_CASE("skip_name advances exactly 2 bytes past a compression pointer", "[dns_wire]")
{
    uint8_t buf[4] = {0xC0, 0x0C, 0xAA, 0xBB};
    size_t offset = 0;
    TEST_ASSERT_TRUE(skip_name(buf, sizeof(buf), offset));
    TEST_ASSERT_EQUAL_size_t(2, offset);
}

TEST_CASE("skip_name fails on a truncated label", "[dns_wire]")
{
    uint8_t buf[] = {4, 't', 'e'};
    size_t offset = 0;
    TEST_ASSERT_FALSE(skip_name(buf, sizeof(buf), offset));
}

// --- scan_answer_section ----------------------------------------------------

TEST_CASE("scan_answer_section handles ancount == 0", "[dns_wire]")
{
    uint8_t buf[4] = {};
    auto scan = scan_answer_section(buf, sizeof(buf), /*answer_start_offset=*/2, /*ancount=*/0);
    TEST_ASSERT_TRUE(scan.has_value());
    TEST_ASSERT_EQUAL_size_t(2, scan->end_offset);
    TEST_ASSERT_EQUAL_UINT32(0, scan->min_ttl);
}

// Builds one RR at `offset`: a 2-byte compression-pointer name, then the
// DNS_ANSWER_RR_FIXED_SIZE (10-byte) type/class/ttl/rdlength block, then
// rdata — returning the offset just past it. Mirrors exactly what
// scan_answer_section expects: skip_name() consumes the 2-byte pointer,
// then the fixed block starts.
size_t append_test_rr(std::vector<uint8_t> &buf, size_t offset, uint32_t ttl,
                       const std::vector<uint8_t> &rdata)
{
    size_t fixed_start = offset + 2; // past the 2-byte compression pointer
    size_t total = fixed_start + DNS_ANSWER_RR_FIXED_SIZE + rdata.size();
    buf.resize(total);
    write_uint16_be(buf.data(), offset, DNS_NAME_COMPRESSION_POINTER);
    write_uint16_be(buf.data(), fixed_start, DNS_TYPE_A);
    write_uint16_be(buf.data(), fixed_start + 2, DNS_CLASS_IN);
    write_uint32_be(buf.data(), fixed_start + 4, ttl);
    write_uint16_be(buf.data(), fixed_start + 8, static_cast<uint16_t>(rdata.size()));
    std::memcpy(buf.data() + fixed_start + DNS_ANSWER_RR_FIXED_SIZE, rdata.data(), rdata.size());
    return total;
}

TEST_CASE("scan_answer_section finds the minimum TTL across RRs", "[dns_wire]")
{
    std::vector<uint8_t> buf(12, 0); // pad so the compression pointer target is plausible
    size_t offset = append_test_rr(buf, buf.size(), /*ttl=*/300, {1, 2, 3, 4});
    offset = append_test_rr(buf, offset, /*ttl=*/60, {5, 6, 7, 8});
    append_test_rr(buf, offset, /*ttl=*/600, {9, 9, 9, 9});

    auto scan = scan_answer_section(buf.data(), buf.size(), /*answer_start_offset=*/12,
                                     /*ancount=*/3);
    TEST_ASSERT_TRUE(scan.has_value());
    TEST_ASSERT_EQUAL_UINT32(60, scan->min_ttl);
    TEST_ASSERT_EQUAL_size_t(buf.size(), scan->end_offset);
}

TEST_CASE("scan_answer_section rejects an rdlength that overruns the buffer", "[dns_wire]")
{
    // 12 (padding) + 2 (name pointer) + 10 (fixed RR fields) = 24, with no
    // room at all for the 100 bytes of rdata the rdlength field claims.
    std::vector<uint8_t> buf(12 + 2 + DNS_ANSWER_RR_FIXED_SIZE, 0);
    write_uint16_be(buf.data(), 12, DNS_NAME_COMPRESSION_POINTER);
    write_uint16_be(buf.data(), 14, DNS_TYPE_A);
    write_uint16_be(buf.data(), 16, DNS_CLASS_IN);
    write_uint32_be(buf.data(), 18, 60);
    write_uint16_be(buf.data(), 22, 100); // claims 100 bytes of rdata that aren't there

    auto scan = scan_answer_section(buf.data(), buf.size(), 12, 1);
    TEST_ASSERT_FALSE(scan.has_value());
}

// --- qtype_to_string ---------------------------------------------------------

TEST_CASE("qtype_to_string recognizes A, AAAA, and everything else", "[dns_wire]")
{
    TEST_ASSERT_EQUAL_STRING("A", qtype_to_string(DNS_TYPE_A));
    TEST_ASSERT_EQUAL_STRING("AAAA", qtype_to_string(DNS_TYPE_AAAA));
    TEST_ASSERT_EQUAL_STRING("OTHER", qtype_to_string(15)); // MX, arbitrary "other"
}

// --- build_a_record_response / build_aaaa_record_response -----------------

TEST_CASE("build_a_record_response lays out header, question, and answer", "[dns_wire]")
{
    auto question = encode_question("test.loc", DNS_TYPE_A);
    std::array<uint8_t, 4> ip = {192, 168, 1, 50};
    uint8_t tx[128];

    auto len = build_a_record_response(/*query_id=*/0x1234, /*query_flags=*/0x0100,
                                        question.data(), question.size(), ip, tx, sizeof(tx));
    TEST_ASSERT_TRUE(len.has_value());

    TEST_ASSERT_EQUAL_UINT16(0x1234, read_uint16_be(tx, 0)); // id echoed
    uint16_t flags = read_uint16_be(tx, 2);
    TEST_ASSERT_EQUAL_UINT16(DNS_RCODE_NOERROR, flags & 0x000F);
    TEST_ASSERT_EQUAL_UINT16(0x0100, flags & 0x0100); // RD echoed
    TEST_ASSERT_EQUAL_UINT16(1, read_uint16_be(tx, 4));  // qdcount
    TEST_ASSERT_EQUAL_UINT16(1, read_uint16_be(tx, 6));  // ancount

    size_t offset = DNS_HEADER_SIZE + question.size();
    TEST_ASSERT_EQUAL_UINT16(DNS_NAME_COMPRESSION_POINTER, read_uint16_be(tx, offset));
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_A, read_uint16_be(tx, offset + 2));
    TEST_ASSERT_EQUAL_UINT16(DNS_CLASS_IN, read_uint16_be(tx, offset + 4));
    // +6 ttl (4 bytes), +10 rdlength, +12 rdata.
    TEST_ASSERT_EQUAL_UINT16(4, read_uint16_be(tx, offset + 10)); // rdlength
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ip.data(), tx + offset + 12, 4);
    TEST_ASSERT_EQUAL_size_t(offset + 12 + 4, *len);
}

TEST_CASE("build_aaaa_record_response lays out a 16-byte answer", "[dns_wire]")
{
    auto question = encode_question("dual.loc", DNS_TYPE_AAAA);
    std::array<uint8_t, 16> ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t tx[128];

    auto len = build_aaaa_record_response(0x5678, 0x0000, question.data(), question.size(), ip,
                                           tx, sizeof(tx));
    TEST_ASSERT_TRUE(len.has_value());

    size_t offset = DNS_HEADER_SIZE + question.size();
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_AAAA, read_uint16_be(tx, offset + 2));
    // +6 ttl (4 bytes), +10 rdlength, +12 rdata.
    TEST_ASSERT_EQUAL_UINT16(16, read_uint16_be(tx, offset + 10)); // rdlength
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ip.data(), tx + offset + 12, 16);
    TEST_ASSERT_EQUAL_size_t(offset + 12 + 16, *len);
}

TEST_CASE("build_a_record_response fails when the buffer is too small", "[dns_wire]")
{
    auto question = encode_question("test.loc", DNS_TYPE_A);
    std::array<uint8_t, 4> ip = {1, 2, 3, 4};
    uint8_t tx[4]; // nowhere near enough
    TEST_ASSERT_FALSE(
        build_a_record_response(1, 0, question.data(), question.size(), ip, tx, sizeof(tx))
            .has_value());
}

// --- build_nxdomain_response / build_nodata_response -----------------------

TEST_CASE("build_nxdomain_response sets RCODE=3 and no answers", "[dns_wire]")
{
    auto question = encode_question("missing.loc", DNS_TYPE_A);
    uint8_t tx[128];
    auto len = build_nxdomain_response(0xAAAA, 0x0100, question.data(), question.size(), tx,
                                        sizeof(tx));
    TEST_ASSERT_TRUE(len.has_value());
    TEST_ASSERT_EQUAL_UINT16(DNS_RCODE_NXDOMAIN, read_uint16_be(tx, 2) & 0x000F);
    TEST_ASSERT_EQUAL_UINT16(0, read_uint16_be(tx, 6)); // ancount
    TEST_ASSERT_EQUAL_size_t(DNS_HEADER_SIZE + question.size(), *len);
}

TEST_CASE("build_nodata_response sets RCODE=0 (NOERROR) and no answers", "[dns_wire]")
{
    auto question = encode_question("aonly.loc", DNS_TYPE_AAAA);
    uint8_t tx[128];
    auto len = build_nodata_response(0xBBBB, 0x0100, question.data(), question.size(), tx,
                                      sizeof(tx));
    TEST_ASSERT_TRUE(len.has_value());
    TEST_ASSERT_EQUAL_UINT16(DNS_RCODE_NOERROR, read_uint16_be(tx, 2) & 0x000F);
    TEST_ASSERT_EQUAL_UINT16(0, read_uint16_be(tx, 6)); // ancount
    TEST_ASSERT_EQUAL_size_t(DNS_HEADER_SIZE + question.size(), *len);
}

// --- build_relayed_response --------------------------------------------------

TEST_CASE("build_relayed_response splices a captured answer section and passes through "
          "rcode/ancount",
          "[dns_wire]")
{
    auto question = encode_question("cached.loc", DNS_TYPE_A);
    std::vector<uint8_t> answer_section = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
                                            10,   0,    0, 1};
    uint8_t tx[128];

    auto len = build_relayed_response(0xCCCC, 0x0100, question.data(), question.size(),
                                       DNS_RCODE_NOERROR, /*ancount=*/1, answer_section.data(),
                                       answer_section.size(), tx, sizeof(tx));
    TEST_ASSERT_TRUE(len.has_value());
    TEST_ASSERT_EQUAL_UINT16(DNS_RCODE_NOERROR, read_uint16_be(tx, 2) & 0x000F);
    TEST_ASSERT_EQUAL_UINT16(1, read_uint16_be(tx, 6)); // ancount

    size_t offset = DNS_HEADER_SIZE + question.size();
    TEST_ASSERT_EQUAL_UINT8_ARRAY(answer_section.data(), tx + offset, answer_section.size());
    TEST_ASSERT_EQUAL_size_t(offset + answer_section.size(), *len);
}

TEST_CASE("build_relayed_response passes through SERVFAIL with zero answers", "[dns_wire]")
{
    auto question = encode_question("timedout.loc", DNS_TYPE_A);
    uint8_t tx[128];
    auto len = build_relayed_response(0xDDDD, 0x0100, question.data(), question.size(),
                                       DNS_RCODE_SERVFAIL, /*ancount=*/0, /*answer_section=*/nullptr,
                                       /*answer_section_len=*/0, tx, sizeof(tx));
    TEST_ASSERT_TRUE(len.has_value());
    TEST_ASSERT_EQUAL_UINT16(DNS_RCODE_SERVFAIL, read_uint16_be(tx, 2) & 0x000F);
    TEST_ASSERT_EQUAL_size_t(DNS_HEADER_SIZE + question.size(), *len);
}

TEST_CASE("build_relayed_response fails when the buffer is too small", "[dns_wire]")
{
    auto question = encode_question("cached.loc", DNS_TYPE_A);
    std::vector<uint8_t> answer_section(100, 0);
    uint8_t tx[8]; // far too small
    TEST_ASSERT_FALSE(build_relayed_response(1, 0, question.data(), question.size(),
                                              DNS_RCODE_NOERROR, 1, answer_section.data(),
                                              answer_section.size(), tx, sizeof(tx))
                          .has_value());
}

extern "C" void app_main(void)
{
    UNITY_BEGIN();
    unity_run_all_tests();
    // ESP-IDF's linux-target port starts the FreeRTOS scheduler before
    // calling app_main and never tears it down when app_main returns —
    // the process would otherwise hang forever after printing results.
    // exit() with UNITY_END()'s failure count gives a real process exit
    // code (0 = all passed), so this doubles as the pass/fail signal for
    // a CI script or `idf.py build && ./build/host_test.elf` from a shell.
    exit(UNITY_END());
}
