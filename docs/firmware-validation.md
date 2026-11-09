# Firmware Validation Evidence

**Scan date:** 2026-11-09  
**Result:** 43 images scanned, 43 passed, 0 failed

## Validation method

The offline verifier reads each supplied 32-bit little-endian SceShell ELF, extracts its sole executable `PT_LOAD` segment, and searches that segment for both internal close-current-application confirmation predicates.

The primary locator derives a 162-byte candidate from a 52-byte invariant core:

```text
candidate = core_match - 0x30
```

A candidate is accepted only when:

- the invariant core occurs exactly once in the executable text segment;
- the complete 162-byte candidate is in bounds;
- the 14-byte entry prefix at `+0x00` matches;
- the 52-byte invariant core at `+0x30` matches;
- the 24-byte comparison/decision block at `+0x70` matches;
- the 12-byte return suffix at `+0x96` matches and ends at the candidate boundary.

The transition locator derives a 106-byte candidate from a 40-byte invariant core:

```text
candidate = transition_core_match - 0x08
```

The transition candidate is accepted only when:

- the transition core occurs exactly once in the executable text segment;
- the complete 106-byte candidate is in bounds;
- the 4-byte entry prefix at `+0x00` matches;
- the 40-byte invariant core at `+0x08` matches;
- the 30-byte comparison/decision block at `+0x34` matches;
- the 17-byte return suffix at `+0x59` matches and ends at the candidate boundary.

Both accepted entries are replaced at runtime with:

```text
00 20 70 47    movs r0, #0; bx lr
```

Offsets below are relative to SceShell text segment 0. They are validation evidence, not a runtime offset table.

## Corpus summary

| Group | Images | Pass | Fail |
| --- | ---: | ---: | ---: |
| Retail | 12 | 12 | 0 |
| Testkit | 9 | 9 | 0 |
| Devkit | 10 | 10 | 0 |
| Internal CEX/devtool | 6 | 6 | 0 |
| DEX/debug/no-watermark | 4 | 4 | 0 |
| Internal 4.00 | 2 | 2 | 0 |
| **Total** | **43** | **43** | **0** |

## Retail

| Firmware labels | Images | Primary offset | Transition offset |
| --- | ---: | ---: | ---: |
| 3.60, 3.61 | 2 | `0x278594` | `0x272530` |
| 3.63 | 1 | `0x278630` | `0x2725CC` |
| 3.65, 3.67, 3.68, 3.69, 3.70, 3.71, 3.72, 3.73, 3.74 | 9 | `0x27895E` | `0x2725E8` |

## Testkit

| Build labels | Images | Primary offset | Transition offset |
| --- | ---: | ---: | ---: |
| 3.600.011, 3.610.011 | 2 | `0x270938` | `0x26A8D4` |
| 3.630.011 | 1 | `0x2709D4` | `0x26A970` |
| 3.650.011, 3.670.011, 3.680.011, 3.700.011, 3.720.011, 3.730.011 | 6 | `0x270D02` | `0x26A98C` |

## Devkit

| Build labels | Images | Primary offset | Transition offset |
| --- | ---: | ---: | ---: |
| 3.600.011, 3.610.011 | 2 | `0x26C1B4` | `0x265FEA` |
| 3.630.011 | 1 | `0x26C250` | `0x266086` |
| 3.650.011, 3.670.011, 3.680.011, 3.690.011, 3.700.011, 3.710.011, 3.730.011 | 7 | `0x26C57E` | `0x2660A2` |

## Internal CEX and devtool

| Internal build label | Class | Primary offset | Transition offset |
| --- | --- | ---: | ---: |
| `3_600_011.I.cex_for_tool.release.type3.qaf` | CEX-for-tool | `0x27889A` | `0x27282A` |
| `3_630_011.I.devtool.release.type3.qaf` | Devtool | `0x26C338` | `0x26616E` |
| `3_650_000.I.cex_for_tool.release.type3.qaf` | CEX-for-tool | `0x278C48` | `0x2728C6` |
| `3_650_011.I.cex_for_tool.release.type3.qaf` | CEX-for-tool | `0x278C64` | `0x2728E2` |
| `3_650_011.I.devtool.release.type3.qaf` | Devtool | `0x26C666` | `0x26618A` |
| `3_720_011.I.devtool.release.type3` | Devtool | `0x26C666` | `0x26618A` |

## DEX, debug, and no-watermark variants

| Build label | Class | Primary offset | Transition offset |
| --- | --- | ---: | ---: |
| `3_650._011.I.cex.release.type3.qaf` | Internal no-watermark CEX | `0x278A46` | `0x2726D0` |
| `3_650._011.I.dex.release.type3.qaf` | Internal no-watermark DEX | `0x270DEA` | `0x26AA74` |
| `3.650 E.dex.release.type3.qaf` | SCE external DEX/debug | `0x270DEA` | `0x26AA74` |
| `3.670 E.dex.release.type3.qaf` | SCE external DEX/debug | `0x270DEA` | `0x26AA74` |

## Internal 4.00

| Build snapshot | Primary offset | Transition offset |
| --- | ---: | ---: |
| `inai400` current decrypted filesystem | `0x278B60` | `0x2727DE` |
| `inai400` older decrypted filesystem | `0x278C48` | `0x2728C6` |

## Representative semantic verification

Representative images from each major class were inspected in IDA/Hex-Rays rather than accepted solely from byte similarity. The primary function was confirmed to select the initial confirmation or direct-start continuation. The direct-start continuation enters the general application-transition routine, whose second predicate can independently construct the same confirmation. Returning zero from both predicates preserves SceShell's existing direct-start and application-close machinery while eliminating both confirmation gates.

| Representative class/build | Primary guard | Transition guard | Direct-start continuation |
| --- | ---: | ---: | ---: |
| Retail 3.60 | `0x278594` | `0x272530` | `0x278636` |
| Retail 3.65–3.74 layout | `0x27895E` | `0x2725E8` | `0x278A00` |
| Testkit 3.600.011 | `0x270938` | `0x26A8D4` | `0x2709DA` |
| Testkit 3.730.011 | `0x270D02` | `0x26A98C` | `0x270DA4` |
| Devkit 3.600.011 | `0x26C1B4` | `0x265FEA` | `0x26C256` |
| Devkit 3.730.011 | `0x26C57E` | `0x2660A2` | `0x26C620` |
| Internal CEX 3.600 | `0x27889A` | `0x27282A` | `0x27893C` |
| Internal devtool 3.650 | `0x26C666` | `0x26618A` | `0x26C708` |
| DEX/debug 3.650 | `0x270DEA` | `0x26AA74` | `0x270E8C` |
| Internal 4.00 | `0x278B60` | `0x2727DE` | `0x278C02` |

The reviewed control flow constructs the normal launch job and closes the current application through SceShell's existing transition path. The plugin does not preserve the already running application.

## On-device confirmation

On 2026-11-09, both patches were verified on a retail 3.60 Vita. Runtime instrumentation recorded the primary offset as `0x278594` and the transition offset as `0x272530`; both `taiInjectData` calls returned valid UIDs and both entries read back as `00 20 70 47`. Launching application B while application A remained active produced no confirmation, application A closed, and application B opened normally. The release build removes the runtime record and all file-I/O instrumentation.

## Interpretation and limits

The 43/43 result establishes structural compatibility with the examined firmware files across retail, testkit, devkit, internal, DEX/debug, no-watermark, and internal 4.00 classes. It does not prove that every future firmware is compatible, and it does not replace on-device execution.

An unexamined firmware can be accepted safely only when both validated structures remain unchanged and unique. Any missing, duplicate, truncated, or altered validation window makes the plugin refuse to patch SceShell.

Additional target classes still require the same two-application launch test. Unrelated-dialog coverage and stock-behavior restoration after removal should also be verified before a broad release claim.
