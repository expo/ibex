#!/usr/bin/env python3
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("normalize-macho-uuid.py")
MACHO_64_LITTLE_ENDIAN = 0xFEEDFACF
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D


def macho(uuid: bytes, *, signed: bool = False, include_uuid: bool = True) -> bytes:
    commands = []
    if include_uuid:
        commands.append(struct.pack("<II16s", LC_UUID, 24, uuid))
    signature = b""
    if signed:
        signature = bytes(range(32))
        commands_size = sum(len(command) for command in commands) + 16
        signature_offset = 32 + commands_size + len(b"stable-payload")
        commands.append(struct.pack("<IIII", LC_CODE_SIGNATURE, 16, signature_offset, len(signature)))
    header = struct.pack(
        "<IiiIIIII",
        MACHO_64_LITTLE_ENDIAN,
        0x0100000C,
        0,
        2,
        len(commands),
        sum(len(command) for command in commands),
        0,
        0,
    )
    return header + b"".join(commands) + b"stable-payload" + signature


class NormalizeMachOUuidTests(unittest.TestCase):
    def run_script(self, path: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(path)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_different_linker_uuids_converge_and_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            left = pathlib.Path(directory, "left")
            right = pathlib.Path(directory, "right")
            left.write_bytes(macho(bytes.fromhex("00" * 16)))
            right.write_bytes(macho(bytes.fromhex("ff" * 16)))

            self.assertEqual(self.run_script(left).returncode, 0)
            self.assertEqual(self.run_script(right).returncode, 0)
            self.assertEqual(left.read_bytes(), right.read_bytes())
            once = left.read_bytes()
            self.assertEqual(self.run_script(left).returncode, 0)
            self.assertEqual(left.read_bytes(), once)

    def test_signed_image_is_refused_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "signed")
            original = macho(bytes(range(16)), signed=True)
            path.write_bytes(original)
            result = self.run_script(path)
            self.assertEqual(result.returncode, 1)
            self.assertIn("code signature", result.stderr)
            self.assertEqual(path.read_bytes(), original)

    def test_missing_uuid_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "missing")
            path.write_bytes(macho(bytes(16), include_uuid=False))
            result = self.run_script(path)
            self.assertEqual(result.returncode, 1)
            self.assertIn("exactly one LC_UUID", result.stderr)


if __name__ == "__main__":
    unittest.main()
