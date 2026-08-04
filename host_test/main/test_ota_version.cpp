// Host-side unit tests for main/ota_version.h/.cpp (Phase 7a) — same
// no-FreeRTOS-dependency, linux-target pattern as test_dns_wire.cpp:
//
//   idf.py --preview set-target linux -C host_test build
//   ./host_test/build/host_test.elf

#include "ota_version.h"
#include "unity.h"

// Not in an anonymous namespace, unlike test_dns_wire.cpp's helpers: these
// need external linkage so test_dns_wire.cpp's app_main (the single merged
// Unity entry point — see its file comment) can RUN_TEST() them via the
// forward declarations there.

void test_parse_valid_with_v_prefix()
{
    auto v = ota_version_parse("v1.2.3");
    TEST_ASSERT_TRUE(v.has_value());
    TEST_ASSERT_EQUAL_UINT(1, v->major);
    TEST_ASSERT_EQUAL_UINT(2, v->minor);
    TEST_ASSERT_EQUAL_UINT(3, v->patch);
}

void test_parse_valid_without_v_prefix()
{
    auto v = ota_version_parse("0.6.0");
    TEST_ASSERT_TRUE(v.has_value());
    TEST_ASSERT_EQUAL_UINT(0, v->major);
    TEST_ASSERT_EQUAL_UINT(6, v->minor);
    TEST_ASSERT_EQUAL_UINT(0, v->patch);
}

void test_parse_tolerates_git_describe_suffix()
{
    auto v = ota_version_parse("v0.6.0-3-gabc1234-dirty");
    TEST_ASSERT_TRUE(v.has_value());
    TEST_ASSERT_EQUAL_UINT(0, v->patch);
}

void test_parse_rejects_empty()
{
    TEST_ASSERT_FALSE(ota_version_parse("").has_value());
}

void test_parse_rejects_garbage()
{
    TEST_ASSERT_FALSE(ota_version_parse("notaversion").has_value());
}

void test_parse_rejects_missing_minor()
{
    TEST_ASSERT_FALSE(ota_version_parse("v1").has_value());
}

void test_is_newer_minor_bump()
{
    TEST_ASSERT_TRUE(ota_version_is_newer("v0.6.0", "v0.7.0"));
}

void test_is_newer_false_when_older()
{
    TEST_ASSERT_FALSE(ota_version_is_newer("v0.7.0", "v0.6.0"));
}

void test_is_newer_false_when_equal()
{
    TEST_ASSERT_FALSE(ota_version_is_newer("v0.6.0", "v0.6.0"));
}

void test_is_newer_patch_bump()
{
    TEST_ASSERT_TRUE(ota_version_is_newer("v0.6.0", "v0.6.1"));
}

void test_is_newer_major_beats_minor_and_patch()
{
    TEST_ASSERT_TRUE(ota_version_is_newer("v0.9.9", "v1.0.0"));
}

void test_is_newer_false_on_unparseable_remote()
{
    TEST_ASSERT_FALSE(ota_version_is_newer("v0.6.0", "garbage"));
}

void test_is_newer_false_on_unparseable_current()
{
    TEST_ASSERT_FALSE(ota_version_is_newer("garbage", "v1.0.0"));
}
