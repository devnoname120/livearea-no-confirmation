#include <psp2/kernel/modulemgr.h>
#include <psp2/types.h>
#include <taihen.h>

#include "plugin.h"

static int get_shell(void *context, LncShellInfo *shell_out)
{
    tai_module_info_t tai_info;
    SceKernelModuleInfo module_info;
    int result;

    (void)context;
    tai_info.size = sizeof(tai_info);
    result = taiGetModuleInfo("SceShell", &tai_info);
    if (result < 0)
        return result;

    module_info.size = sizeof(module_info);
    result = sceKernelGetModuleInfo(tai_info.modid, &module_info);
    if (result < 0)
        return result;

    if (module_info.segments[LNC_SHELL_TEXT_SEGMENT].vaddr == NULL ||
        module_info.segments[LNC_SHELL_TEXT_SEGMENT].memsz == 0)
        return -1;

    shell_out->modid = tai_info.modid;
    shell_out->text = module_info.segments[LNC_SHELL_TEXT_SEGMENT].vaddr;
    shell_out->text_size =
        module_info.segments[LNC_SHELL_TEXT_SEGMENT].memsz;
    return 0;
}

static LncUid inject_data(
    void *context,
    LncUid modid,
    int segment_index,
    uint32_t offset,
    const void *data,
    size_t size)
{
    (void)context;
    return taiInjectData(modid, segment_index, offset, data, size);
}

static int release_data(void *context, LncUid injection_uid)
{
    (void)context;
    return taiInjectRelease(injection_uid);
}

static const LncPlatformOps platform_ops = {
    .context = NULL,
    .get_shell = get_shell,
    .inject = inject_data,
    .release = release_data,
};

static LncPluginState plugin_state = {
    .primary_injection_uid = LNC_INVALID_UID,
    .transition_injection_uid = LNC_INVALID_UID,
};

int module_start(SceSize argc, const void *args)
{
    LncPluginResult result;

    (void)argc;
    (void)args;
    result = lnc_plugin_start(&plugin_state, &platform_ops);
    return result == LNC_PLUGIN_OK || result == LNC_PLUGIN_ROLLBACK_FAILED
        ? SCE_KERNEL_START_SUCCESS
        : SCE_KERNEL_START_FAILED;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    return lnc_plugin_stop(&plugin_state, &platform_ops) == LNC_PLUGIN_OK
        ? SCE_KERNEL_STOP_SUCCESS
        : SCE_KERNEL_STOP_CANCEL;
}
