#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import re
import struct
import sys
from typing import Iterable, TextIO


PT_LOAD = 1
PF_X = 1
ELF32_HEADER_SIZE = 52
ELF32_PROGRAM_HEADER_SIZE = 32
CANDIDATE_SIZE = 0xA2
CORE_OFFSET = 0x30
DECISION_OFFSET = 0x70
SUFFIX_OFFSET = 0x96
TRANSITION_CANDIDATE_SIZE = 0x6A
TRANSITION_CORE_OFFSET = 0x08
TRANSITION_DECISION_OFFSET = 0x34
TRANSITION_SUFFIX_OFFSET = 0x59
MINIMUM_FIRMWARE = (3, 60)

ENTRY_PREFIX = bytes.fromhex(
    "70 b5 16 1c 05 46 cc b2 01 d1 01 20 48 e0"
)
CORE_PATTERN = bytes.fromhex(
    "d3 f8 ac 30 03 b1 5a 68 9a 42 30 d0 d2 f8 08 e0 "
    "de f8 1c 10 88 42 03 d1 be f1 00 0f 05 d1 26 e0 "
    "02 b1 52 68 9a 42 f1 d1 21 e0 14 b1 e8 6e 86 45 "
    "1d d0 70 46"
)
DECISION_BLOCK = bytes.fromhex(
    "99 42 08 bf 90 42 01 d1 01 20 11 e0 00 23 02 22 "
    "99 42 08 bf 90 42 0a d1"
)
RETURN_SUFFIX = bytes.fromhex(
    "00 28 01 d1 01 20 00 e0 00 20 70 bd"
)
TRANSITION_ENTRY_PREFIX = bytes.fromhex(
    "10 b5 04 1c"
)
TRANSITION_CORE_PATTERN = bytes.fromhex(
    "01 28 2c d0 e3 6e 00 2b 29 d0 5a 6b 00 2a 26 d0 "
    "d9 6c 01 29 23 d0 02 29 21 d0 03 29 1f d0 50 6b "
    "01 28 1c d1 13 f1 54 00"
)
TRANSITION_DECISION_BLOCK = bytes.fromhex(
    "00 23 00 22 99 42 08 bf 90 42 01 d1 00 23 06 e0 "
    "01 21 20 1c ff f7 79 ff 00 28 0a d0 01 23"
)
TRANSITION_RETURN_SUFFIX = bytes.fromhex(
    "10 00 68 00 21 00 22 ff f7 93 fc 00 e0 00 20 10 bd"
)

VERSION_COMPONENT = re.compile(r"^(\d+)\.(\d{2,3})(?:\.\d+)?$")


def read_executable_segment(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < ELF32_HEADER_SIZE or data[:4] != b"\x7fELF" or \
            data[4] != 1 or data[5] != 1:
        raise ValueError("not a 32-bit little-endian ELF32 image")

    program_offset = struct.unpack_from("<I", data, 28)[0]
    program_entry_size, program_count = struct.unpack_from("<HH", data, 42)
    if program_entry_size < ELF32_PROGRAM_HEADER_SIZE:
        raise ValueError("invalid ELF32 program-header entry size")
    if program_offset > len(data) or program_count > \
            (len(data) - program_offset) // program_entry_size:
        raise ValueError("ELF32 program-header table exceeds the file")

    executable_segments: list[bytes] = []
    for index in range(program_count):
        entry_offset = program_offset + index * program_entry_size
        fields = struct.unpack_from("<IIIIIIII", data, entry_offset)
        p_type, p_offset, _vaddr, _paddr, p_filesz, _memsz, p_flags, _align = \
            fields
        if p_type != PT_LOAD or not (p_flags & PF_X):
            continue
        if p_filesz == 0:
            raise ValueError("empty executable PT_LOAD segment")
        if p_offset > len(data) or p_filesz > len(data) - p_offset:
            raise ValueError("executable PT_LOAD segment exceeds the file")
        executable_segments.append(data[p_offset:p_offset + p_filesz])

    if len(executable_segments) != 1:
        raise ValueError(
            f"expected one executable PT_LOAD segment, found "
            f"{len(executable_segments)}"
        )
    return executable_segments[0]


def _find_candidate(
        text: bytes,
        *,
        candidate_size: int,
        core_offset: int,
        decision_offset: int,
        suffix_offset: int,
        entry_prefix: bytes,
        core_pattern: bytes,
        decision_block: bytes,
        return_suffix: bytes,
        label: str) -> int:
    occurrences: list[int] = []
    start = 0
    while start <= len(text) - len(core_pattern):
        offset = text.find(core_pattern, start)
        if offset < 0:
            break
        occurrences.append(offset)
        start = offset + 1

    if not occurrences:
        raise ValueError(f"no {label}core occurrence")
    if len(occurrences) != 1:
        raise ValueError(
            f"multiple {label}core occurrences: {len(occurrences)}"
        )

    matched_core_offset = occurrences[0]
    if matched_core_offset < core_offset:
        raise ValueError(
            f"{label}candidate begins before the text segment"
        )
    candidate = matched_core_offset - core_offset
    if candidate > len(text) or candidate_size > len(text) - candidate:
        raise ValueError(f"{label}candidate extends beyond the text segment")
    if text[candidate:candidate + len(entry_prefix)] != entry_prefix:
        raise ValueError(f"{label}entry validation failed")
    if text[candidate + core_offset:
            candidate + core_offset + len(core_pattern)] != core_pattern:
        raise ValueError(f"{label}core validation failed")
    if text[candidate + decision_offset:
            candidate + decision_offset + len(decision_block)] != \
            decision_block:
        raise ValueError(f"{label}decision-block validation failed")
    if text[candidate + suffix_offset:
            candidate + suffix_offset + len(return_suffix)] != return_suffix:
        raise ValueError(f"{label}return-suffix validation failed")
    return candidate


def find_candidate(text: bytes) -> int:
    return _find_candidate(
        text,
        candidate_size=CANDIDATE_SIZE,
        core_offset=CORE_OFFSET,
        decision_offset=DECISION_OFFSET,
        suffix_offset=SUFFIX_OFFSET,
        entry_prefix=ENTRY_PREFIX,
        core_pattern=CORE_PATTERN,
        decision_block=DECISION_BLOCK,
        return_suffix=RETURN_SUFFIX,
        label="",
    )


def find_transition_candidate(text: bytes) -> int:
    return _find_candidate(
        text,
        candidate_size=TRANSITION_CANDIDATE_SIZE,
        core_offset=TRANSITION_CORE_OFFSET,
        decision_offset=TRANSITION_DECISION_OFFSET,
        suffix_offset=TRANSITION_SUFFIX_OFFSET,
        entry_prefix=TRANSITION_ENTRY_PREFIX,
        core_pattern=TRANSITION_CORE_PATTERN,
        decision_block=TRANSITION_DECISION_BLOCK,
        return_suffix=TRANSITION_RETURN_SUFFIX,
        label="transition ",
    )


def path_metadata(path: Path) -> tuple[str, str, tuple[int, int] | None]:
    normalized = path.as_posix().lower()
    if "/4.00_ina/" in normalized:
        target_class = "internal-4.00"
    elif "/internal (no watermarks)/" in normalized:
        target_class = "internal-no-watermark"
    elif "/external/official/" in normalized:
        target_class = "retail"
    elif "/external/testkit/" in normalized:
        target_class = "testkit"
    elif "/external/devkit/" in normalized:
        target_class = "devkit"
    elif "/sce/internal/" in normalized:
        target_class = "internal"
    elif "/sce/external/" in normalized:
        target_class = "sce-external"
    else:
        target_class = "unknown"

    for component in path.parts:
        if component.startswith("4.00_ina"):
            return target_class, "4.00", (4, 0)
        match = VERSION_COMPONENT.match(component)
        if match is None:
            continue
        major = int(match.group(1))
        minor_text = match.group(2)
        minor = int(minor_text[:2])
        return target_class, component, (major, minor)
    return target_class, "unknown", None


def discover_images(inputs: Iterable[Path]) -> list[Path]:
    discovered: dict[Path, None] = {}
    for source in inputs:
        source = source.expanduser()
        if source.is_file():
            discovered[source.resolve()] = None
            continue
        if not source.is_dir():
            raise ValueError(f"input does not exist: {source}")
        for candidate in source.rglob("shell.elf"):
            _target_class, _label, version = path_metadata(candidate)
            if version is None or version < MINIMUM_FIRMWARE:
                continue
            discovered[candidate.resolve()] = None
    return list(discovered)


def scan_image(path: Path) -> tuple[
        str,
        str,
        tuple[int, int] | None,
        int | None,
        int | None,
        str | None]:
    target_class, version_label, version = path_metadata(path)
    try:
        text = read_executable_segment(path)
        primary_offset = find_candidate(text)
        transition_offset = find_transition_candidate(text)
    except (OSError, ValueError) as error:
        return target_class, version_label, version, None, None, str(error)
    return (
        target_class,
        version_label,
        version,
        primary_offset,
        transition_offset,
        None,
    )


def run(inputs: Iterable[Path], output: TextIO) -> int:
    try:
        images = discover_images(inputs)
    except ValueError as error:
        print(f"ERROR\t{error}", file=output)
        print("summary images=0 pass=0 fail=1", file=output)
        return 1

    if not images:
        print("summary images=0 pass=0 fail=0", file=output)
        return 1

    records = []
    for path in images:
        target_class, label, version, primary, transition, error = \
            scan_image(path)
        records.append((
            target_class,
            version if version is not None else (999, 999),
            label,
            path,
            primary,
            transition,
            error,
        ))
    records.sort(key=lambda record: (record[0], record[1], str(record[3])))

    passed = 0
    failed = 0
    for target_class, _version, label, path, primary, transition, error in \
            records:
        if error is None:
            passed += 1
            print(
                f"PASS\t{target_class}\t{label}\t"
                f"primary=0x{primary:x}\ttransition=0x{transition:x}\t"
                f"{path}",
                file=output,
            )
        else:
            failed += 1
            reason = error.replace("\t", " ").replace("\n", " ")
            print(
                f"FAIL\t{target_class}\t{label}\t-\t{reason}\t{path}",
                file=output,
            )

    print(
        f"summary images={len(records)} pass={passed} fail={failed}",
        file=output,
    )
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate SceShell launch-confirmation signatures"
    )
    parser.add_argument("inputs", nargs="+", type=Path)
    arguments = parser.parse_args(argv)
    return run(arguments.inputs, sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
