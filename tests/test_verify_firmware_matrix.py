from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import re
import struct
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "verify_firmware_matrix.py"
SPEC = importlib.util.spec_from_file_location("firmware_verifier", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

ELF_HEADER_SIZE = 52
PROGRAM_HEADER_SIZE = 32
SEGMENT_FILE_OFFSET = 0x100


def make_candidate() -> bytearray:
    candidate = bytearray([0xA5] * verifier.CANDIDATE_SIZE)
    candidate[:len(verifier.ENTRY_PREFIX)] = verifier.ENTRY_PREFIX
    start = verifier.CORE_OFFSET
    candidate[start:start + len(verifier.CORE_PATTERN)] = \
        verifier.CORE_PATTERN
    start = verifier.DECISION_OFFSET
    candidate[start:start + len(verifier.DECISION_BLOCK)] = \
        verifier.DECISION_BLOCK
    start = verifier.SUFFIX_OFFSET
    candidate[start:start + len(verifier.RETURN_SUFFIX)] = \
        verifier.RETURN_SUFFIX
    return candidate


def make_transition_candidate() -> bytearray:
    candidate = bytearray([0xA5] * verifier.TRANSITION_CANDIDATE_SIZE)
    candidate[:len(verifier.TRANSITION_ENTRY_PREFIX)] = \
        verifier.TRANSITION_ENTRY_PREFIX
    start = verifier.TRANSITION_CORE_OFFSET
    candidate[start:start + len(verifier.TRANSITION_CORE_PATTERN)] = \
        verifier.TRANSITION_CORE_PATTERN
    start = verifier.TRANSITION_DECISION_OFFSET
    candidate[start:start + len(verifier.TRANSITION_DECISION_BLOCK)] = \
        verifier.TRANSITION_DECISION_BLOCK
    start = verifier.TRANSITION_SUFFIX_OFFSET
    candidate[start:start + len(verifier.TRANSITION_RETURN_SUFFIX)] = \
        verifier.TRANSITION_RETURN_SUFFIX
    return candidate


def make_segment(
        offset: int = 37,
        transition_offset: int = 256,
        size: int = 512) -> bytes:
    segment = bytearray(size)
    candidate = make_candidate()
    segment[offset:offset + len(candidate)] = candidate
    transition = make_transition_candidate()
    segment[transition_offset:transition_offset + len(transition)] = transition
    return bytes(segment)


def make_elf(segment: bytes, executable: bool = True) -> bytes:
    data = bytearray(SEGMENT_FILE_OFFSET + len(segment))
    data[:4] = b"\x7fELF"
    data[4] = 1
    data[5] = 1
    data[6] = 1
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        data,
        16,
        2,
        0x28,
        1,
        0,
        ELF_HEADER_SIZE,
        0,
        0,
        ELF_HEADER_SIZE,
        PROGRAM_HEADER_SIZE,
        1,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIIIIIII",
        data,
        ELF_HEADER_SIZE,
        verifier.PT_LOAD,
        SEGMENT_FILE_OFFSET,
        0x81000000,
        0x81000000,
        len(segment),
        len(segment),
        5 if executable else 4,
        0x1000,
    )
    data[SEGMENT_FILE_OFFSET:] = segment
    return bytes(data)


class VerifierTests(unittest.TestCase):
    def test_valid_elf_reports_segment_offset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shell.elf"
            path.write_bytes(make_elf(make_segment(offset=37)))
            text = verifier.read_executable_segment(path)
            self.assertEqual(verifier.find_candidate(text), 37)
            self.assertEqual(verifier.find_transition_candidate(text), 256)

    def test_no_match_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "no core occurrence"):
            verifier.find_candidate(bytes(512))

    def test_duplicate_core_is_rejected(self) -> None:
        text = bytearray(make_segment(offset=0, size=512))
        text[320:320 + len(verifier.CORE_PATTERN)] = verifier.CORE_PATTERN
        with self.assertRaisesRegex(ValueError, "multiple core occurrences"):
            verifier.find_candidate(bytes(text))

    def test_corrupt_entry_is_rejected(self) -> None:
        text = bytearray(make_segment(offset=37))
        text[37] ^= 1
        with self.assertRaisesRegex(ValueError, "entry validation"):
            verifier.find_candidate(bytes(text))

    def test_transition_no_match_is_rejected(self) -> None:
        text = bytearray(make_segment())
        text[256:256 + verifier.TRANSITION_CANDIDATE_SIZE] = \
            bytes(verifier.TRANSITION_CANDIDATE_SIZE)
        with self.assertRaisesRegex(ValueError, "no transition core occurrence"):
            verifier.find_transition_candidate(bytes(text))

    def test_duplicate_transition_core_is_rejected(self) -> None:
        text = bytearray(make_segment())
        text[400:400 + len(verifier.TRANSITION_CORE_PATTERN)] = \
            verifier.TRANSITION_CORE_PATTERN
        with self.assertRaisesRegex(
                ValueError, "multiple transition core occurrences"):
            verifier.find_transition_candidate(bytes(text))

    def test_corrupt_transition_entry_is_rejected(self) -> None:
        text = bytearray(make_segment())
        text[256] ^= 1
        with self.assertRaisesRegex(
                ValueError, "transition entry validation"):
            verifier.find_transition_candidate(bytes(text))

    def test_non_elf_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shell.elf"
            path.write_bytes(b"not an elf")
            with self.assertRaisesRegex(ValueError, "ELF32"):
                verifier.read_executable_segment(path)

    def test_truncated_program_headers_are_rejected(self) -> None:
        data = make_elf(make_segment())[:ELF_HEADER_SIZE + 8]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shell.elf"
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "program-header table"):
                verifier.read_executable_segment(path)

    def test_missing_executable_segment_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shell.elf"
            path.write_bytes(make_elf(make_segment(), executable=False))
            with self.assertRaisesRegex(ValueError, "executable PT_LOAD"):
                verifier.read_executable_segment(path)

    def test_aggregate_failure_sets_nonzero_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "external" / "official" / "3.74" / \
                "fs_dec" / "vs0" / "vsh" / "shell" / "shell.elf"
            invalid = root / "external" / "testkit" / "3.730.011" / \
                "fs_dec" / "vs0" / "vsh" / "shell" / "shell.elf"
            valid.parent.mkdir(parents=True)
            invalid.parent.mkdir(parents=True)
            valid.write_bytes(make_elf(make_segment()))
            invalid.write_bytes(make_elf(bytes(512)))
            output = io.StringIO()
            self.assertEqual(verifier.run([root], output), 1)
            report = output.getvalue()
            self.assertIn("images=2 pass=1 fail=1", report)

    def test_success_report_contains_both_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shell.elf"
            path.write_bytes(make_elf(make_segment()))
            output = io.StringIO()
            self.assertEqual(verifier.run([path], output), 0)
            report = output.getvalue()
            self.assertIn("primary=0x25", report)
            self.assertIn("transition=0x100", report)

    def test_python_patterns_match_c_arrays(self) -> None:
        source = (ROOT / "src" / "signature.c").read_text()
        pattern = re.compile(
            r"static const uint8_t "
            r"(entry_prefix|core_pattern|decision_block|return_suffix|"
            r"transition_entry_prefix|transition_core_pattern|"
            r"transition_decision_block|transition_return_suffix)"
            r"\[\] = \{(.*?)\};",
            re.DOTALL,
        )
        arrays = {
            name: bytes(int(value, 16) for value in
                re.findall(r"0x([0-9A-Fa-f]{2})", body))
            for name, body in pattern.findall(source)
        }
        self.assertEqual(arrays["entry_prefix"], verifier.ENTRY_PREFIX)
        self.assertEqual(arrays["core_pattern"], verifier.CORE_PATTERN)
        self.assertEqual(arrays["decision_block"], verifier.DECISION_BLOCK)
        self.assertEqual(arrays["return_suffix"], verifier.RETURN_SUFFIX)
        self.assertEqual(
            arrays["transition_entry_prefix"],
            verifier.TRANSITION_ENTRY_PREFIX,
        )
        self.assertEqual(
            arrays["transition_core_pattern"],
            verifier.TRANSITION_CORE_PATTERN,
        )
        self.assertEqual(
            arrays["transition_decision_block"],
            verifier.TRANSITION_DECISION_BLOCK,
        )
        self.assertEqual(
            arrays["transition_return_suffix"],
            verifier.TRANSITION_RETURN_SUFFIX,
        )


if __name__ == "__main__":
    unittest.main()
