#ifndef LIVEAREA_NO_CONFIRMATION_PLUGIN_H
#define LIVEAREA_NO_CONFIRMATION_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#define LNC_INVALID_UID (-1)
#define LNC_SHELL_TEXT_SEGMENT 0

typedef int32_t LncUid;

typedef struct LncShellInfo {
    LncUid modid;
    const uint8_t *text;
    size_t text_size;
} LncShellInfo;

typedef struct LncPlatformOps {
    void *context;
    int (*get_shell)(void *context, LncShellInfo *shell_out);
    LncUid (*inject)(
        void *context,
        LncUid modid,
        int segment_index,
        uint32_t offset,
        const void *data,
        size_t size);
    int (*release)(void *context, LncUid injection_uid);
} LncPlatformOps;

typedef struct LncPluginState {
    LncUid primary_injection_uid;
    LncUid transition_injection_uid;
} LncPluginState;

typedef enum LncPluginResult {
    LNC_PLUGIN_OK = 0,
    LNC_PLUGIN_INVALID_ARGUMENT = -100,
    LNC_PLUGIN_ALREADY_ACTIVE = -101,
    LNC_PLUGIN_SHELL_LOOKUP_FAILED = -102,
    LNC_PLUGIN_INVALID_SHELL = -103,
    LNC_PLUGIN_SIGNATURE_FAILED = -104,
    LNC_PLUGIN_INJECTION_FAILED = -105,
    LNC_PLUGIN_RELEASE_FAILED = -106,
    LNC_PLUGIN_ROLLBACK_FAILED = -107
} LncPluginResult;

void lnc_plugin_state_init(LncPluginState *state);
LncPluginResult lnc_plugin_start(
    LncPluginState *state,
    const LncPlatformOps *ops);
LncPluginResult lnc_plugin_stop(
    LncPluginState *state,
    const LncPlatformOps *ops);

#endif
