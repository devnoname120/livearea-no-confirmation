#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fixture.h"
#include "plugin.h"

#define TEST_TEXT_SIZE 512U
#define TEST_PRIMARY_OFFSET 37U
#define TEST_TRANSITION_OFFSET 256U
#define TEST_CALL_CAPACITY 4U

typedef struct MockPlatform {
    uint8_t text[TEST_TEXT_SIZE];
    LncShellInfo shell;
    int get_shell_result;
    LncUid inject_results[TEST_CALL_CAPACITY];
    int release_results[TEST_CALL_CAPACITY];
    unsigned int get_shell_calls;
    unsigned int inject_calls;
    unsigned int release_calls;
    LncUid inject_modids[TEST_CALL_CAPACITY];
    int inject_segments[TEST_CALL_CAPACITY];
    uint32_t inject_offsets[TEST_CALL_CAPACITY];
    uint8_t inject_data[TEST_CALL_CAPACITY][8];
    size_t inject_sizes[TEST_CALL_CAPACITY];
    LncUid release_uids[TEST_CALL_CAPACITY];
} MockPlatform;

static void mock_init(MockPlatform *mock)
{
    memset(mock, 0, sizeof(*mock));
    lnc_test_place_candidate(
        mock->text, sizeof(mock->text), TEST_PRIMARY_OFFSET);
    lnc_test_place_transition_candidate(
        mock->text, sizeof(mock->text), TEST_TRANSITION_OFFSET);
    mock->shell.modid = 42;
    mock->shell.text = mock->text;
    mock->shell.text_size = sizeof(mock->text);
    mock->inject_results[0] = 73;
    mock->inject_results[1] = 74;
}

static int mock_get_shell(void *context, LncShellInfo *shell_out)
{
    MockPlatform *mock = context;
    ++mock->get_shell_calls;
    if (mock->get_shell_result < 0)
        return mock->get_shell_result;
    *shell_out = mock->shell;
    return mock->get_shell_result;
}

static LncUid mock_inject(
    void *context,
    LncUid modid,
    int segment_index,
    uint32_t offset,
    const void *data,
    size_t size)
{
    MockPlatform *mock = context;
    unsigned int call = mock->inject_calls++;

    assert(call < TEST_CALL_CAPACITY);
    assert(size <= sizeof(mock->inject_data[call]));
    mock->inject_modids[call] = modid;
    mock->inject_segments[call] = segment_index;
    mock->inject_offsets[call] = offset;
    mock->inject_sizes[call] = size;
    memcpy(mock->inject_data[call], data, size);
    return mock->inject_results[call];
}

static int mock_release(void *context, LncUid injection_uid)
{
    MockPlatform *mock = context;
    unsigned int call = mock->release_calls++;

    assert(call < TEST_CALL_CAPACITY);
    mock->release_uids[call] = injection_uid;
    return mock->release_results[call];
}

static LncPlatformOps mock_ops(MockPlatform *mock)
{
    LncPlatformOps ops = {
        .context = mock,
        .get_shell = mock_get_shell,
        .inject = mock_inject,
        .release = mock_release,
    };
    return ops;
}

static void assert_false_return_patch(
    const MockPlatform *mock,
    unsigned int call,
    uint32_t expected_offset)
{
    static const uint8_t expected_patch[] = {0x00, 0x20, 0x70, 0x47};

    assert(mock->inject_modids[call] == mock->shell.modid);
    assert(mock->inject_segments[call] == LNC_SHELL_TEXT_SEGMENT);
    assert(mock->inject_offsets[call] == expected_offset);
    assert(mock->inject_sizes[call] == sizeof(expected_patch));
    assert(memcmp(mock->inject_data[call],
        expected_patch, sizeof(expected_patch)) == 0);
}

static void assert_inactive(const LncPluginState *state)
{
    assert(state->primary_injection_uid == LNC_INVALID_UID);
    assert(state->transition_injection_uid == LNC_INVALID_UID);
}

static void test_start_injects_both_false_returns(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_OK);
    assert(mock.get_shell_calls == 1);
    assert(mock.inject_calls == 2);
    assert(mock.release_calls == 0);
    assert_false_return_patch(&mock, 0, TEST_PRIMARY_OFFSET);
    assert_false_return_patch(&mock, 1, TEST_TRANSITION_OFFSET);
    assert(state.primary_injection_uid == mock.inject_results[0]);
    assert(state.transition_injection_uid == mock.inject_results[1]);
}

static void test_lookup_failure_does_not_inject(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    mock.get_shell_result = -7;
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) ==
        LNC_PLUGIN_SHELL_LOOKUP_FAILED);
    assert(mock.inject_calls == 0);
    assert_inactive(&state);
}

static void test_null_text_does_not_inject(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    mock.shell.text = NULL;
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_INVALID_SHELL);
    assert(mock.inject_calls == 0);
    assert_inactive(&state);
}

static void test_empty_text_does_not_inject(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    mock.shell.text_size = 0;
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_INVALID_SHELL);
    assert(mock.inject_calls == 0);
    assert_inactive(&state);
}

static void test_invalid_module_id_does_not_inject(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    mock.shell.modid = -1;
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_INVALID_SHELL);
    assert(mock.inject_calls == 0);
    assert_inactive(&state);
}

static void test_primary_signature_failure_does_not_inject(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    memset(mock.text + TEST_PRIMARY_OFFSET, 0, LNC_NEEDS_CONFIRM_SIZE);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) ==
        LNC_PLUGIN_SIGNATURE_FAILED);
    assert(mock.inject_calls == 0);
    assert_inactive(&state);
}

static void test_transition_signature_failure_does_not_inject(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    memset(mock.text + TEST_TRANSITION_OFFSET,
        0, LNC_TRANSITION_CONFIRM_SIZE);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) ==
        LNC_PLUGIN_SIGNATURE_FAILED);
    assert(mock.inject_calls == 0);
    assert_inactive(&state);
}

static void test_primary_injection_failure_keeps_state_inactive(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    mock.inject_results[0] = -9;
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) ==
        LNC_PLUGIN_INJECTION_FAILED);
    assert(mock.inject_calls == 1);
    assert(mock.release_calls == 0);
    assert_inactive(&state);
}

static void test_transition_injection_failure_rolls_back_primary(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    mock.inject_results[1] = -9;
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) ==
        LNC_PLUGIN_INJECTION_FAILED);
    assert(mock.inject_calls == 2);
    assert(mock.release_calls == 1);
    assert(mock.release_uids[0] == mock.inject_results[0]);
    assert_inactive(&state);
}

static void test_transition_injection_rollback_failure_retains_primary(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    mock.inject_results[1] = -9;
    mock.release_results[0] = -11;
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_ROLLBACK_FAILED);
    assert(mock.inject_calls == 2);
    assert(mock.release_calls == 1);
    assert(state.primary_injection_uid == mock.inject_results[0]);
    assert(state.transition_injection_uid == LNC_INVALID_UID);
}

static void test_second_start_is_rejected(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_OK);
    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_ALREADY_ACTIVE);
    assert(mock.inject_calls == 2);
}

static void test_stop_without_injection_is_noop(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);

    assert(lnc_plugin_stop(&state, &ops) == LNC_PLUGIN_OK);
    assert(mock.release_calls == 0);
}

static void test_stop_releases_both_injections_in_reverse_order(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);
    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_OK);

    assert(lnc_plugin_stop(&state, &ops) == LNC_PLUGIN_OK);
    assert(mock.release_calls == 2);
    assert(mock.release_uids[0] == mock.inject_results[1]);
    assert(mock.release_uids[1] == mock.inject_results[0]);
    assert_inactive(&state);
}

static void test_transition_release_failure_allows_primary_release(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);
    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_OK);

    mock.release_results[0] = -11;
    assert(lnc_plugin_stop(&state, &ops) == LNC_PLUGIN_RELEASE_FAILED);
    assert(mock.release_calls == 2);
    assert(mock.release_uids[0] == mock.inject_results[1]);
    assert(mock.release_uids[1] == mock.inject_results[0]);
    assert(state.transition_injection_uid == mock.inject_results[1]);
    assert(state.primary_injection_uid == LNC_INVALID_UID);

    assert(lnc_plugin_stop(&state, &ops) == LNC_PLUGIN_OK);
    assert(mock.release_calls == 3);
    assert(mock.release_uids[2] == mock.inject_results[1]);
    assert_inactive(&state);
}

static void test_primary_release_failure_retains_primary_for_retry(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;

    mock_init(&mock);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);
    assert(lnc_plugin_start(&state, &ops) == LNC_PLUGIN_OK);

    mock.release_results[1] = -11;
    assert(lnc_plugin_stop(&state, &ops) == LNC_PLUGIN_RELEASE_FAILED);
    assert(mock.release_calls == 2);
    assert(state.transition_injection_uid == LNC_INVALID_UID);
    assert(state.primary_injection_uid == mock.inject_results[0]);

    assert(lnc_plugin_stop(&state, &ops) == LNC_PLUGIN_OK);
    assert(mock.release_calls == 3);
    assert(mock.release_uids[2] == mock.inject_results[0]);
    assert_inactive(&state);
}

static void test_invalid_operations_are_rejected(void)
{
    MockPlatform mock;
    LncPluginState state;
    LncPlatformOps ops;
    LncPlatformOps missing;

    mock_init(&mock);
    lnc_plugin_state_init(&state);
    ops = mock_ops(&mock);
    memset(&missing, 0, sizeof(missing));

    assert(lnc_plugin_start(NULL, &ops) == LNC_PLUGIN_INVALID_ARGUMENT);
    assert(lnc_plugin_start(&state, NULL) == LNC_PLUGIN_INVALID_ARGUMENT);
    assert(lnc_plugin_start(&state, &missing) ==
        LNC_PLUGIN_INVALID_ARGUMENT);
    missing = ops;
    missing.release = NULL;
    assert(lnc_plugin_start(&state, &missing) ==
        LNC_PLUGIN_INVALID_ARGUMENT);
    assert(lnc_plugin_stop(NULL, &ops) == LNC_PLUGIN_INVALID_ARGUMENT);
    assert(lnc_plugin_stop(&state, NULL) == LNC_PLUGIN_INVALID_ARGUMENT);
    memset(&missing, 0, sizeof(missing));
    assert(lnc_plugin_stop(&state, &missing) ==
        LNC_PLUGIN_INVALID_ARGUMENT);
    lnc_plugin_state_init(NULL);
}

int main(void)
{
    test_start_injects_both_false_returns();
    test_lookup_failure_does_not_inject();
    test_null_text_does_not_inject();
    test_empty_text_does_not_inject();
    test_invalid_module_id_does_not_inject();
    test_primary_signature_failure_does_not_inject();
    test_transition_signature_failure_does_not_inject();
    test_primary_injection_failure_keeps_state_inactive();
    test_transition_injection_failure_rolls_back_primary();
    test_transition_injection_rollback_failure_retains_primary();
    test_second_start_is_rejected();
    test_stop_without_injection_is_noop();
    test_stop_releases_both_injections_in_reverse_order();
    test_transition_release_failure_allows_primary_release();
    test_primary_release_failure_retains_primary_for_retry();
    test_invalid_operations_are_rejected();
    puts("plugin tests passed");
    return 0;
}
