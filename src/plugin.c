#include "plugin.h"

#include "signature.h"

static const uint8_t false_return_patch[] = {0x00, 0x20, 0x70, 0x47};

void lnc_plugin_state_init(LncPluginState *state)
{
    if (state != NULL) {
        state->primary_injection_uid = LNC_INVALID_UID;
        state->transition_injection_uid = LNC_INVALID_UID;
    }
}

LncPluginResult lnc_plugin_start(
    LncPluginState *state,
    const LncPlatformOps *ops)
{
    LncShellInfo shell;
    uint32_t primary_offset;
    uint32_t transition_offset;
    LncUid primary_injection_uid;
    LncUid transition_injection_uid;

    if (state == NULL || ops == NULL || ops->get_shell == NULL ||
        ops->inject == NULL || ops->release == NULL)
        return LNC_PLUGIN_INVALID_ARGUMENT;
    if (state->primary_injection_uid >= 0 ||
        state->transition_injection_uid >= 0)
        return LNC_PLUGIN_ALREADY_ACTIVE;
    if (ops->get_shell(ops->context, &shell) < 0)
        return LNC_PLUGIN_SHELL_LOOKUP_FAILED;
    if (shell.modid < 0 || shell.text == NULL || shell.text_size == 0)
        return LNC_PLUGIN_INVALID_SHELL;
    if (lnc_find_needs_confirm(
            shell.text, shell.text_size, &primary_offset) !=
            LNC_SIGNATURE_OK ||
        lnc_find_transition_confirm(
            shell.text, shell.text_size, &transition_offset) !=
            LNC_SIGNATURE_OK)
        return LNC_PLUGIN_SIGNATURE_FAILED;

    primary_injection_uid = ops->inject(
        ops->context,
        shell.modid,
        LNC_SHELL_TEXT_SEGMENT,
        primary_offset,
        false_return_patch,
        sizeof(false_return_patch));
    if (primary_injection_uid < 0)
        return LNC_PLUGIN_INJECTION_FAILED;

    state->primary_injection_uid = primary_injection_uid;
    transition_injection_uid = ops->inject(
        ops->context,
        shell.modid,
        LNC_SHELL_TEXT_SEGMENT,
        transition_offset,
        false_return_patch,
        sizeof(false_return_patch));
    if (transition_injection_uid < 0) {
        if (ops->release(ops->context, primary_injection_uid) < 0)
            return LNC_PLUGIN_ROLLBACK_FAILED;
        state->primary_injection_uid = LNC_INVALID_UID;
        return LNC_PLUGIN_INJECTION_FAILED;
    }

    state->transition_injection_uid = transition_injection_uid;
    return LNC_PLUGIN_OK;
}

LncPluginResult lnc_plugin_stop(
    LncPluginState *state,
    const LncPlatformOps *ops)
{
    int failed = 0;

    if (state == NULL || ops == NULL || ops->release == NULL)
        return LNC_PLUGIN_INVALID_ARGUMENT;

    if (state->transition_injection_uid >= 0) {
        if (ops->release(
                ops->context, state->transition_injection_uid) < 0) {
            failed = 1;
        } else {
            state->transition_injection_uid = LNC_INVALID_UID;
        }
    }

    if (state->primary_injection_uid >= 0) {
        if (ops->release(
                ops->context, state->primary_injection_uid) < 0) {
            failed = 1;
        } else {
            state->primary_injection_uid = LNC_INVALID_UID;
        }
    }

    return failed ? LNC_PLUGIN_RELEASE_FAILED : LNC_PLUGIN_OK;
}
