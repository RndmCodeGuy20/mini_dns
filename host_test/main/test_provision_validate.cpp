// Host-side unit tests for main/provision_validate.h/.cpp (Phase 7b) — same
// no-FreeRTOS-dependency, linux-target pattern as test_dns_wire.cpp:
//
//   idf.py --preview set-target linux -C host_test build
//   ./host_test/build/host_test.elf

#include "provision_validate.h"
#include "unity.h"

// Not in an anonymous namespace, unlike test_dns_wire.cpp's helpers: these
// need external linkage so test_dns_wire.cpp's app_main (the single merged
// Unity entry point — see its file comment) can RUN_TEST() them via the
// forward declarations there.

void test_ssid_empty_rejected()
{
    TEST_ASSERT_EQUAL(ProvisionValidation::kSsidEmpty, provision_validate("", "somepassword"));
}

void test_ssid_length_1_ok()
{
    TEST_ASSERT_EQUAL(ProvisionValidation::kOk, provision_validate("a", "somepassword"));
}

void test_ssid_length_32_ok()
{
    std::string ssid(32, 'a');
    TEST_ASSERT_EQUAL(ProvisionValidation::kOk, provision_validate(ssid, "somepassword"));
}

void test_ssid_length_33_too_long()
{
    std::string ssid(33, 'a');
    TEST_ASSERT_EQUAL(ProvisionValidation::kSsidTooLong, provision_validate(ssid, "somepassword"));
}

void test_password_empty_is_open_network_ok()
{
    TEST_ASSERT_EQUAL(ProvisionValidation::kOk, provision_validate("myssid", ""));
}

void test_password_length_7_too_short()
{
    std::string password(7, 'p');
    TEST_ASSERT_EQUAL(ProvisionValidation::kPasswordTooShort, provision_validate("myssid", password));
}

void test_password_length_8_ok()
{
    std::string password(8, 'p');
    TEST_ASSERT_EQUAL(ProvisionValidation::kOk, provision_validate("myssid", password));
}

void test_password_length_63_ok()
{
    std::string password(63, 'p');
    TEST_ASSERT_EQUAL(ProvisionValidation::kOk, provision_validate("myssid", password));
}

void test_password_length_64_too_long()
{
    std::string password(64, 'p');
    TEST_ASSERT_EQUAL(ProvisionValidation::kPasswordTooLong, provision_validate("myssid", password));
}

void test_ssid_multibyte_utf8_within_byte_limit_ok()
{
    // 16 codepoints of the 3-byte UTF-8 character U+00E9 encoded as 0xC3 0xA9
    // is wrong (that's 2 bytes) — use a 3-byte CJK codepoint instead so 10
    // codepoints == 30 bytes, safely under 32, confirming size() (bytes) is
    // used rather than any codepoint-aware length.
    std::string ssid;
    for (int i = 0; i < 10; ++i) {
        ssid += "\xE4\xBD\xA0"; // U+4F60 "you", 3 bytes in UTF-8
    }
    TEST_ASSERT_EQUAL_size_t(30, ssid.size());
    TEST_ASSERT_EQUAL(ProvisionValidation::kOk, provision_validate(ssid, "somepassword"));
}
