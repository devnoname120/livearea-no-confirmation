# LiveArea No Confirmation

`livearea_no_confirmation` is a taiHEN user plugin for SceShell. It bypasses the confirmation shown when launching an application would close another application that is still running.

The plugin does not keep both applications resident. SceShell still closes the current application and starts the requested application through its normal direct-start path; the plugin only suppresses the intermediate close-current-application prompt.

## Scope

The patch targets two internal SceShell predicates in the application-launch path. The first selects between the initial confirmation path and direct start; the second is the transition guard reached by that direct-start path. Both must report false to bypass the prompt without replacing SceShell's launch machinery. The plugin does not intentionally affect generic CommonDialog users, parental-control prompts, error dialogs, destructive-operation confirmations, or application-manager resource limits.

At startup, the plugin:

1. resolves the loaded `SceShell` module;
2. uniquely validates the 162-byte primary predicate and the 106-byte transition predicate in text segment 0;
3. replaces the first four bytes of both functions with `movs r0, #0; bx lr` through `taiInjectData`;
4. retains both injection UIDs so `module_stop` can restore the original bytes with `taiInjectRelease`.

Both locators are fail-closed. Missing, duplicate, truncated, or structurally changed candidates are rejected before any write. If the second injection fails after the first succeeds, the plugin releases the first before startup fails. If that release itself fails, the module remains loaded with the retained UID so unload can retry instead of abandoning an active patch. There is no firmware-version switch or fallback offset table.

## Compatibility

Offline validation on 2026-11-09 covered 43 independently supplied SceShell images with 43 passes and zero failures. The corpus includes:

- retail firmware 3.60 through 3.74 where dumps were available;
- testkit builds from 3.600.011 through 3.730.011 where dumps were available;
- devkit builds from 3.600.011 through 3.730.011 where dumps were available;
- internal CEX, devtool, no-watermark, DEX/debug, and SCE external variants;
- two available internal 4.00 images.

Representative decompilation checks confirmed the same two-stage confirmation-versus-direct-start control flow across the examined target classes. See [`docs/firmware-validation.md`](docs/firmware-validation.md) for the exact corpus and both offsets.

This establishes structural compatibility with the examined files; it is not equivalent to on-device behavioral testing. A future firmware is accepted only when the complete validated SceShell structure remains unchanged. A numerically newer version is not automatically supported.

## Installation

Copy the built plugin to:

```text
ur0:tai/livearea_no_confirmation.suprx
```

Add it beneath `*main` in `ur0:tai/config.txt`:

```text
*main
ur0:tai/livearea_no_confirmation.suprx
```

Perform a full reboot after installation, replacement, or removal. SceShell and `*main` plugins are long-lived, so reloading only the configuration is insufficient.

To remove the plugin, delete or comment out its `*main` entry, remove the SUPRX if desired, and reboot. Stock confirmation behavior returns after the reboot.

## Building

The reproducible release build uses this pinned VitaSDK image:

```sh
docker run --rm --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -w /work \
  vitasdk/vitasdk@sha256:fd82d88ff456d118eef16533ebf9a3a6ae0e292684fb8a3a35f15f0707b4692d \
  sh -ec 'cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build'
```

The output is:

```text
build/livearea_no_confirmation.suprx
```

The project links only the taiHEN and kernel module-manager stubs required by the adapter. It does not include Sony SDK material or firmware images.

## Host tests

Run the C locator and lifecycle suites under AddressSanitizer and UndefinedBehaviorSanitizer, followed by the Python ELF-verifier suite:

```sh
python3 tests/run.py
```

## Firmware validation

The verifier consumes separately supplied firmware ELFs and is not a runtime dependency:

```sh
python3 tools/verify_firmware_matrix.py /path/to/decrypted/firmware/root
```

It discovers eligible `shell.elf` files, extracts the sole executable ELF32 `PT_LOAD` segment, requires exactly one occurrence of each invariant core, validates both entry, decision, and return windows, and returns a non-zero status if either candidate fails.

## Hardware verification

The dual-patch behavior was confirmed on a retail 3.60 Vita on 2026-11-09: application A was launched, LiveArea was reopened while A remained active, and application B was launched. The prompt did not appear, application A was no longer running, and application B opened normally. The deployed diagnostic build differed from the release only by recording the two resolved offsets, injection UIDs, and post-injection bytes; the release build contains no logging or file-I/O instrumentation.

Other target classes and unrelated-dialog coverage should still use this sequence:

Before treating a target class as behaviorally verified, test this sequence on hardware:

1. launch application A;
2. return to LiveArea while A remains active;
3. launch application B that normally produces the close-current-application confirmation;
4. verify that the confirmation does not appear;
5. verify that A closes and B starts normally;
6. verify that unrelated confirmation and error dialogs still appear;
7. reboot and repeat;
8. remove the plugin entry, reboot, and verify that stock behavior returns.

Offline matrix validation does not substitute for executing this scenario on each additional target class.
