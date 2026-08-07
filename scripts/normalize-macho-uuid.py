#!/usr/bin/env python3
"""Replace one unsigned thin Mach-O LC_UUID with a content-derived UUID."""

import hashlib
import os
import pathlib
import struct
import sys
import tempfile


MACHO_64_LITTLE_ENDIAN = 0xFEEDFACF
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D


# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog — make cataloged UUIDs deterministic
def normalized_bytes(path: pathlib.Path) -> tuple[bytes, str]:
    data = bytearray(path.read_bytes())
    if len(data) < 32:
        raise ValueError("file is shorter than a Mach-O 64 header")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != MACHO_64_LITTLE_ENDIAN:
        raise ValueError("file is not a thin little-endian Mach-O 64 image")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    commands_end = 32 + sizeofcmds
    if commands_end > len(data):
        raise ValueError("Mach-O load-command table exceeds the file")

    offset = 32
    uuid_offsets: list[int] = []
    for _ in range(ncmds):
        if offset + 8 > commands_end:
            raise ValueError("Mach-O load command header exceeds the table")
        command, command_size = struct.unpack_from("<II", data, offset)
        if command_size < 8 or offset + command_size > commands_end:
            raise ValueError("Mach-O load command has an invalid size")
        if command == LC_UUID:
            if command_size != 24:
                raise ValueError("LC_UUID does not have the required 24-byte size")
            uuid_offsets.append(offset + 8)
        elif command == LC_CODE_SIGNATURE:
            if command_size != 16:
                raise ValueError("LC_CODE_SIGNATURE does not have the required 16-byte size")
            _, signature_size = struct.unpack_from("<II", data, offset + 8)
            if signature_size != 0:
                raise ValueError("refusing to normalize a Mach-O with a code signature")
        offset += command_size
    if offset != commands_end:
        raise ValueError("Mach-O load commands do not fill sizeofcmds")
    if len(uuid_offsets) != 1:
        raise ValueError(f"expected exactly one LC_UUID, found {len(uuid_offsets)}")

    uuid_offset = uuid_offsets[0]
    data[uuid_offset : uuid_offset + 16] = bytes(16)
    uuid = bytearray(hashlib.sha256(data).digest()[:16])
    uuid[6] = (uuid[6] & 0x0F) | 0x50
    uuid[8] = (uuid[8] & 0x3F) | 0x80
    data[uuid_offset : uuid_offset + 16] = uuid
    uuid_text = (
        f"{uuid[0:4].hex()}-{uuid[4:6].hex()}-{uuid[6:8].hex()}-"
        f"{uuid[8:10].hex()}-{uuid[10:16].hex()}"
    ).upper()
    return bytes(data), uuid_text


def normalize(path: pathlib.Path) -> str:
    output, uuid_text = normalized_bytes(path)
    mode = path.stat().st_mode
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = pathlib.Path(handle.name)
        handle.write(output)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return uuid_text


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {pathlib.Path(sys.argv[0]).name} MACHO", file=sys.stderr)
        return 2
    path = pathlib.Path(sys.argv[1])
    try:
        uuid_text = normalize(path)
    except (OSError, ValueError) as error:
        print(f"Mach-O UUID normalization refused: {error}", file=sys.stderr)
        return 1
    print(f"normalizedMachOUuid={uuid_text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
