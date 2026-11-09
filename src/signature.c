#include "signature.h"

#define CORE_OFFSET 0x30U
#define DECISION_OFFSET 0x70U
#define SUFFIX_OFFSET 0x96U
#define TRANSITION_CORE_OFFSET 0x08U
#define TRANSITION_DECISION_OFFSET 0x34U
#define TRANSITION_SUFFIX_OFFSET 0x59U

static const uint8_t entry_prefix[] = {
    0x70, 0xB5, 0x16, 0x1C, 0x05, 0x46, 0xCC,
    0xB2, 0x01, 0xD1, 0x01, 0x20, 0x48, 0xE0
};

static const uint8_t core_pattern[] = {
    0xD3, 0xF8, 0xAC, 0x30, 0x03, 0xB1, 0x5A, 0x68,
    0x9A, 0x42, 0x30, 0xD0, 0xD2, 0xF8, 0x08, 0xE0,
    0xDE, 0xF8, 0x1C, 0x10, 0x88, 0x42, 0x03, 0xD1,
    0xBE, 0xF1, 0x00, 0x0F, 0x05, 0xD1, 0x26, 0xE0,
    0x02, 0xB1, 0x52, 0x68, 0x9A, 0x42, 0xF1, 0xD1,
    0x21, 0xE0, 0x14, 0xB1, 0xE8, 0x6E, 0x86, 0x45,
    0x1D, 0xD0, 0x70, 0x46
};

static const uint8_t decision_block[] = {
    0x99, 0x42, 0x08, 0xBF, 0x90, 0x42, 0x01, 0xD1,
    0x01, 0x20, 0x11, 0xE0, 0x00, 0x23, 0x02, 0x22,
    0x99, 0x42, 0x08, 0xBF, 0x90, 0x42, 0x0A, 0xD1
};

static const uint8_t return_suffix[] = {
    0x00, 0x28, 0x01, 0xD1, 0x01, 0x20,
    0x00, 0xE0, 0x00, 0x20, 0x70, 0xBD
};

static const uint8_t transition_entry_prefix[] = {
    0x10, 0xB5, 0x04, 0x1C
};

static const uint8_t transition_core_pattern[] = {
    0x01, 0x28, 0x2C, 0xD0, 0xE3, 0x6E, 0x00, 0x2B,
    0x29, 0xD0, 0x5A, 0x6B, 0x00, 0x2A, 0x26, 0xD0,
    0xD9, 0x6C, 0x01, 0x29, 0x23, 0xD0, 0x02, 0x29,
    0x21, 0xD0, 0x03, 0x29, 0x1F, 0xD0, 0x50, 0x6B,
    0x01, 0x28, 0x1C, 0xD1, 0x13, 0xF1, 0x54, 0x00
};

static const uint8_t transition_decision_block[] = {
    0x00, 0x23, 0x00, 0x22, 0x99, 0x42, 0x08, 0xBF,
    0x90, 0x42, 0x01, 0xD1, 0x00, 0x23, 0x06, 0xE0,
    0x01, 0x21, 0x20, 0x1C, 0xFF, 0xF7, 0x79, 0xFF,
    0x00, 0x28, 0x0A, 0xD0, 0x01, 0x23
};

static const uint8_t transition_return_suffix[] = {
    0x10, 0x00, 0x68, 0x00, 0x21, 0x00, 0x22, 0xFF,
    0xF7, 0x93, 0xFC, 0x00, 0xE0, 0x00, 0x20, 0x10,
    0xBD
};

_Static_assert(CORE_OFFSET + sizeof(core_pattern) <=
    LNC_NEEDS_CONFIRM_SIZE, "core window exceeds candidate");
_Static_assert(DECISION_OFFSET + sizeof(decision_block) <=
    LNC_NEEDS_CONFIRM_SIZE, "decision window exceeds candidate");
_Static_assert(SUFFIX_OFFSET + sizeof(return_suffix) ==
    LNC_NEEDS_CONFIRM_SIZE, "suffix must end at candidate boundary");
_Static_assert(TRANSITION_CORE_OFFSET + sizeof(transition_core_pattern) <=
    LNC_TRANSITION_CONFIRM_SIZE, "transition core window exceeds candidate");
_Static_assert(
    TRANSITION_DECISION_OFFSET + sizeof(transition_decision_block) <=
    LNC_TRANSITION_CONFIRM_SIZE,
    "transition decision window exceeds candidate");
_Static_assert(
    TRANSITION_SUFFIX_OFFSET + sizeof(transition_return_suffix) ==
    LNC_TRANSITION_CONFIRM_SIZE,
    "transition suffix must end at candidate boundary");

static int bytes_equal(
    const uint8_t *left,
    const uint8_t *right,
    size_t size)
{
    size_t index;

    for (index = 0; index < size; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

LncSignatureResult lnc_find_needs_confirm(
    const uint8_t *text,
    size_t text_size,
    uint32_t *offset_out)
{
    size_t index;
    size_t core_offset = 0;
    size_t candidate;
    uint32_t candidate_offset;
    int found = 0;

    if (text == NULL || offset_out == NULL)
        return LNC_SIGNATURE_INVALID_ARGUMENT;
    if (text_size < sizeof(core_pattern))
        return LNC_SIGNATURE_NO_MATCH;

    for (index = 0; index <= text_size - sizeof(core_pattern); ++index) {
        if (!bytes_equal(text + index, core_pattern, sizeof(core_pattern)))
            continue;
        if (found)
            return LNC_SIGNATURE_MULTIPLE_MATCHES;
        core_offset = index;
        found = 1;
    }

    if (!found)
        return LNC_SIGNATURE_NO_MATCH;
    if (core_offset < CORE_OFFSET)
        return LNC_SIGNATURE_OUT_OF_BOUNDS;

    candidate = core_offset - CORE_OFFSET;
    candidate_offset = (uint32_t)candidate;
    if ((size_t)candidate_offset != candidate)
        return LNC_SIGNATURE_OFFSET_OVERFLOW;
    if (candidate > text_size ||
        LNC_NEEDS_CONFIRM_SIZE > text_size - candidate)
        return LNC_SIGNATURE_OUT_OF_BOUNDS;

    if (!bytes_equal(text + candidate,
            entry_prefix, sizeof(entry_prefix)) ||
        !bytes_equal(text + candidate + CORE_OFFSET,
            core_pattern, sizeof(core_pattern)) ||
        !bytes_equal(text + candidate + DECISION_OFFSET,
            decision_block, sizeof(decision_block)) ||
        !bytes_equal(text + candidate + SUFFIX_OFFSET,
            return_suffix, sizeof(return_suffix)))
        return LNC_SIGNATURE_VALIDATION_FAILED;

    *offset_out = candidate_offset;
    return LNC_SIGNATURE_OK;
}

LncSignatureResult lnc_find_transition_confirm(
    const uint8_t *text,
    size_t text_size,
    uint32_t *offset_out)
{
    size_t index;
    size_t core_offset = 0;
    size_t candidate;
    uint32_t candidate_offset;
    int found = 0;

    if (text == NULL || offset_out == NULL)
        return LNC_SIGNATURE_INVALID_ARGUMENT;
    if (text_size < sizeof(transition_core_pattern))
        return LNC_SIGNATURE_NO_MATCH;

    for (index = 0;
        index <= text_size - sizeof(transition_core_pattern);
        ++index) {
        if (!bytes_equal(
                text + index,
                transition_core_pattern,
                sizeof(transition_core_pattern)))
            continue;
        if (found)
            return LNC_SIGNATURE_MULTIPLE_MATCHES;
        core_offset = index;
        found = 1;
    }

    if (!found)
        return LNC_SIGNATURE_NO_MATCH;
    if (core_offset < TRANSITION_CORE_OFFSET)
        return LNC_SIGNATURE_OUT_OF_BOUNDS;

    candidate = core_offset - TRANSITION_CORE_OFFSET;
    candidate_offset = (uint32_t)candidate;
    if ((size_t)candidate_offset != candidate)
        return LNC_SIGNATURE_OFFSET_OVERFLOW;
    if (candidate > text_size ||
        LNC_TRANSITION_CONFIRM_SIZE > text_size - candidate)
        return LNC_SIGNATURE_OUT_OF_BOUNDS;

    if (!bytes_equal(text + candidate,
            transition_entry_prefix, sizeof(transition_entry_prefix)) ||
        !bytes_equal(text + candidate + TRANSITION_CORE_OFFSET,
            transition_core_pattern, sizeof(transition_core_pattern)) ||
        !bytes_equal(text + candidate + TRANSITION_DECISION_OFFSET,
            transition_decision_block, sizeof(transition_decision_block)) ||
        !bytes_equal(text + candidate + TRANSITION_SUFFIX_OFFSET,
            transition_return_suffix, sizeof(transition_return_suffix)))
        return LNC_SIGNATURE_VALIDATION_FAILED;

    *offset_out = candidate_offset;
    return LNC_SIGNATURE_OK;
}
