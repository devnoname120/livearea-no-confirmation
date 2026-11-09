#ifndef LIVEAREA_NO_CONFIRMATION_SIGNATURE_H
#define LIVEAREA_NO_CONFIRMATION_SIGNATURE_H

#include <stddef.h>
#include <stdint.h>

#define LNC_NEEDS_CONFIRM_SIZE 0xA2U
#define LNC_TRANSITION_CONFIRM_SIZE 0x6AU

typedef enum LncSignatureResult {
    LNC_SIGNATURE_OK = 0,
    LNC_SIGNATURE_INVALID_ARGUMENT = -1,
    LNC_SIGNATURE_NO_MATCH = -2,
    LNC_SIGNATURE_MULTIPLE_MATCHES = -3,
    LNC_SIGNATURE_OUT_OF_BOUNDS = -4,
    LNC_SIGNATURE_VALIDATION_FAILED = -5,
    LNC_SIGNATURE_OFFSET_OVERFLOW = -6
} LncSignatureResult;

LncSignatureResult lnc_find_needs_confirm(
    const uint8_t *text,
    size_t text_size,
    uint32_t *offset_out);

LncSignatureResult lnc_find_transition_confirm(
    const uint8_t *text,
    size_t text_size,
    uint32_t *offset_out);

#endif
