#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fixture.h"
#include "signature.h"

static void expect_failure_keeps_output(
    const uint8_t *text,
    size_t text_size,
    LncSignatureResult expected)
{
    uint32_t offset = 0xA5A5A5A5U;
    assert(lnc_find_needs_confirm(text, text_size, &offset) == expected);
    assert(offset == 0xA5A5A5A5U);
}

static void expect_transition_failure_keeps_output(
    const uint8_t *text,
    size_t text_size,
    LncSignatureResult expected)
{
    uint32_t offset = 0xA5A5A5A5U;
    assert(lnc_find_transition_confirm(text, text_size, &offset) == expected);
    assert(offset == 0xA5A5A5A5U);
}

static void test_valid_candidate_at_start(void)
{
    uint8_t text[LNC_NEEDS_CONFIRM_SIZE];
    uint32_t offset = UINT32_MAX;
    lnc_test_place_candidate(text, sizeof(text), 0);
    assert(lnc_find_needs_confirm(text, sizeof(text), &offset) ==
        LNC_SIGNATURE_OK);
    assert(offset == 0);
}

static void test_valid_candidate_in_middle(void)
{
    uint8_t text[384] = {0};
    uint32_t offset = UINT32_MAX;
    lnc_test_place_candidate(text, sizeof(text), 37);
    assert(lnc_find_needs_confirm(text, sizeof(text), &offset) ==
        LNC_SIGNATURE_OK);
    assert(offset == 37);
}

static void test_valid_candidate_at_last_position(void)
{
    uint8_t text[384] = {0};
    uint32_t offset = UINT32_MAX;
    size_t expected = sizeof(text) - LNC_NEEDS_CONFIRM_SIZE;
    lnc_test_place_candidate(text, sizeof(text), expected);
    assert(lnc_find_needs_confirm(text, sizeof(text), &offset) ==
        LNC_SIGNATURE_OK);
    assert(offset == expected);
}

static void test_no_match(void)
{
    uint8_t text[384] = {0};
    expect_failure_keeps_output(text, sizeof(text), LNC_SIGNATURE_NO_MATCH);
}

static void test_core_before_candidate_start(void)
{
    uint8_t text[256] = {0};
    memcpy(text + 7, lnc_test_core, sizeof(lnc_test_core));
    expect_failure_keeps_output(text, sizeof(text),
        LNC_SIGNATURE_OUT_OF_BOUNDS);
}

static void test_truncated_candidate(void)
{
    uint8_t text[LNC_TEST_CORE_OFFSET + sizeof(lnc_test_core)] = {0};
    memcpy(text + LNC_TEST_CORE_OFFSET,
        lnc_test_core, sizeof(lnc_test_core));
    expect_failure_keeps_output(text, sizeof(text),
        LNC_SIGNATURE_OUT_OF_BOUNDS);
}

static void test_corrupt_entry(void)
{
    uint8_t text[384] = {0};
    lnc_test_place_candidate(text, sizeof(text), 17);
    text[17] ^= 1U;
    expect_failure_keeps_output(text, sizeof(text),
        LNC_SIGNATURE_VALIDATION_FAILED);
}

static void test_corrupt_decision(void)
{
    uint8_t text[384] = {0};
    lnc_test_place_candidate(text, sizeof(text), 17);
    text[17 + LNC_TEST_DECISION_OFFSET] ^= 1U;
    expect_failure_keeps_output(text, sizeof(text),
        LNC_SIGNATURE_VALIDATION_FAILED);
}

static void test_corrupt_suffix(void)
{
    uint8_t text[384] = {0};
    lnc_test_place_candidate(text, sizeof(text), 17);
    text[17 + LNC_TEST_SUFFIX_OFFSET] ^= 1U;
    expect_failure_keeps_output(text, sizeof(text),
        LNC_SIGNATURE_VALIDATION_FAILED);
}

static void test_two_valid_candidates(void)
{
    uint8_t text[512] = {0};
    lnc_test_place_candidate(text, sizeof(text), 0);
    lnc_test_place_candidate(text, sizeof(text), 256);
    expect_failure_keeps_output(text, sizeof(text),
        LNC_SIGNATURE_MULTIPLE_MATCHES);
}

static void test_valid_plus_invalid_core_is_ambiguous(void)
{
    uint8_t text[512] = {0};
    lnc_test_place_candidate(text, sizeof(text), 0);
    memcpy(text + 320, lnc_test_core, sizeof(lnc_test_core));
    expect_failure_keeps_output(text, sizeof(text),
        LNC_SIGNATURE_MULTIPLE_MATCHES);
}

static void test_invalid_arguments(void)
{
    uint8_t text[1] = {0};
    uint32_t offset = 0;
    assert(lnc_find_needs_confirm(NULL, sizeof(text), &offset) ==
        LNC_SIGNATURE_INVALID_ARGUMENT);
    assert(lnc_find_needs_confirm(text, sizeof(text), NULL) ==
        LNC_SIGNATURE_INVALID_ARGUMENT);
}

static void test_transition_valid_candidate_at_start(void)
{
    uint8_t text[LNC_TRANSITION_CONFIRM_SIZE];
    uint32_t offset = UINT32_MAX;
    lnc_test_place_transition_candidate(text, sizeof(text), 0);
    assert(lnc_find_transition_confirm(text, sizeof(text), &offset) ==
        LNC_SIGNATURE_OK);
    assert(offset == 0);
}

static void test_transition_valid_candidate_in_middle(void)
{
    uint8_t text[384] = {0};
    uint32_t offset = UINT32_MAX;
    lnc_test_place_transition_candidate(text, sizeof(text), 83);
    assert(lnc_find_transition_confirm(text, sizeof(text), &offset) ==
        LNC_SIGNATURE_OK);
    assert(offset == 83);
}

static void test_transition_valid_candidate_at_last_position(void)
{
    uint8_t text[384] = {0};
    uint32_t offset = UINT32_MAX;
    size_t expected = sizeof(text) - LNC_TRANSITION_CONFIRM_SIZE;
    lnc_test_place_transition_candidate(text, sizeof(text), expected);
    assert(lnc_find_transition_confirm(text, sizeof(text), &offset) ==
        LNC_SIGNATURE_OK);
    assert(offset == expected);
}

static void test_transition_no_match(void)
{
    uint8_t text[384] = {0};
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_NO_MATCH);
}

static void test_transition_core_before_candidate_start(void)
{
    uint8_t text[256] = {0};
    memcpy(text + 7,
        lnc_test_transition_core, sizeof(lnc_test_transition_core));
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_OUT_OF_BOUNDS);
}

static void test_transition_truncated_candidate(void)
{
    uint8_t text[
        LNC_TEST_TRANSITION_CORE_OFFSET + sizeof(lnc_test_transition_core)] =
        {0};
    memcpy(text + LNC_TEST_TRANSITION_CORE_OFFSET,
        lnc_test_transition_core, sizeof(lnc_test_transition_core));
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_OUT_OF_BOUNDS);
}

static void test_transition_corrupt_entry(void)
{
    uint8_t text[384] = {0};
    lnc_test_place_transition_candidate(text, sizeof(text), 17);
    text[17] ^= 1U;
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_VALIDATION_FAILED);
}

static void test_transition_corrupt_decision(void)
{
    uint8_t text[384] = {0};
    lnc_test_place_transition_candidate(text, sizeof(text), 17);
    text[17 + LNC_TEST_TRANSITION_DECISION_OFFSET] ^= 1U;
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_VALIDATION_FAILED);
}

static void test_transition_corrupt_suffix(void)
{
    uint8_t text[384] = {0};
    lnc_test_place_transition_candidate(text, sizeof(text), 17);
    text[17 + LNC_TEST_TRANSITION_SUFFIX_OFFSET] ^= 1U;
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_VALIDATION_FAILED);
}

static void test_transition_two_valid_candidates(void)
{
    uint8_t text[512] = {0};
    lnc_test_place_transition_candidate(text, sizeof(text), 0);
    lnc_test_place_transition_candidate(text, sizeof(text), 256);
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_MULTIPLE_MATCHES);
}

static void test_transition_valid_plus_invalid_core_is_ambiguous(void)
{
    uint8_t text[512] = {0};
    lnc_test_place_transition_candidate(text, sizeof(text), 0);
    memcpy(text + 320,
        lnc_test_transition_core, sizeof(lnc_test_transition_core));
    expect_transition_failure_keeps_output(
        text, sizeof(text), LNC_SIGNATURE_MULTIPLE_MATCHES);
}

static void test_transition_invalid_arguments(void)
{
    uint8_t text[1] = {0};
    uint32_t offset = 0;
    assert(lnc_find_transition_confirm(NULL, sizeof(text), &offset) ==
        LNC_SIGNATURE_INVALID_ARGUMENT);
    assert(lnc_find_transition_confirm(text, sizeof(text), NULL) ==
        LNC_SIGNATURE_INVALID_ARGUMENT);
}

int main(void)
{
    test_valid_candidate_at_start();
    test_valid_candidate_in_middle();
    test_valid_candidate_at_last_position();
    test_no_match();
    test_core_before_candidate_start();
    test_truncated_candidate();
    test_corrupt_entry();
    test_corrupt_decision();
    test_corrupt_suffix();
    test_two_valid_candidates();
    test_valid_plus_invalid_core_is_ambiguous();
    test_invalid_arguments();
    test_transition_valid_candidate_at_start();
    test_transition_valid_candidate_in_middle();
    test_transition_valid_candidate_at_last_position();
    test_transition_no_match();
    test_transition_core_before_candidate_start();
    test_transition_truncated_candidate();
    test_transition_corrupt_entry();
    test_transition_corrupt_decision();
    test_transition_corrupt_suffix();
    test_transition_two_valid_candidates();
    test_transition_valid_plus_invalid_core_is_ambiguous();
    test_transition_invalid_arguments();
    puts("signature tests passed");
    return 0;
}
