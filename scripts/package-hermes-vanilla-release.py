#!/usr/bin/env python3
"""Create a byte-deterministic tar.gz from a staged Hermes bundle."""

from __future__ import annotations

import gzip
import pathlib
import sys
import tarfile


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"package-hermes-vanilla-release: {message}")


def entries(root: pathlib.Path) -> list[pathlib.Path]:
    result: list[pathlib.Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            fail(f"bundle contains a symlink: {path}")
        if not path.is_dir() and not path.is_file():
            fail(f"bundle contains a non-regular entry: {path}")
        result.append(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def mode(path: pathlib.Path) -> int:
    if path.is_dir():
        return 0o755
    relative = path.as_posix()
    if "/bin/" in f"/{relative}" or path.suffix.lower() == ".exe":
        return 0o755
    return 0o644


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: package-hermes-vanilla-release.py <bundle-dir> <archive.tar.gz>")
    root = pathlib.Path(sys.argv[1]).resolve(strict=True)
    output = pathlib.Path(sys.argv[2]).resolve()
    if not root.is_dir():
        fail(f"bundle root is not a directory: {root}")
    if output == root or root in output.parents:
        fail("output archive must be outside the bundle root")
    members = entries(root)
    if not members:
        fail("bundle is empty")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for path in members:
                    name = path.relative_to(root).as_posix()
                    info = tarfile.TarInfo(name + ("/" if path.is_dir() else ""))
                    info.mode = mode(path)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
                    else:
                        info.size = path.stat().st_size
                        with path.open("rb") as source:
                            archive.addfile(info, source)
    print(output)


if __name__ == "__main__":
    main()
