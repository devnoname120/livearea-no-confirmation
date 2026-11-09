#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build-host"
COMMON_FLAGS = [
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-pedantic",
    "-O1",
    "-g",
    "-fsanitize=address,undefined",
    "-fno-omit-frame-pointer",
    "-Isrc",
    "-Itests",
]


def build_and_run(name: str, sources: list[str]) -> None:
    compiler = os.environ.get("CC", "cc")
    output = BUILD / name
    command = [compiler, *COMMON_FLAGS, *sources, "-o", str(output)]
    subprocess.run(command, cwd=ROOT, check=True)
    subprocess.run([str(output)], cwd=ROOT, check=True)


def main() -> int:
    BUILD.mkdir(exist_ok=True)
    build_and_run(
        "test_signature",
        ["tests/test_signature.c", "src/signature.c"],
    )
    build_and_run(
        "test_plugin",
        ["tests/test_plugin.c", "src/plugin.c", "src/signature.c"],
    )
    subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_verify_firmware_matrix"],
        cwd=ROOT,
        check=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode) from error
