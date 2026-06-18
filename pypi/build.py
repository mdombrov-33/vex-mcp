#!/usr/bin/env python3
"""Assemble the PyPI wheels for publishing.

Usage: python pypi/build.py <version> <dist-dir> [out-dir]
  <version>   release version, e.g. 0.1.5 (no leading "v")
  <dist-dir>  directory holding the GitHub Release archives
              (vex-mcp-<triple>.tar.gz and the windows .zip)
  [out-dir]   where to write the wheels (default: pypi/dist)

A wheel is just a zip with a fixed layout. Each one here drops the prebuilt
binary into the wheel's `scripts` slot, so `pip install` / `uvx` put `vex-mcp`
on PATH. Unlike npm there is no facade package: PyPI serves the wheel whose
platform tag matches the host. The binaries are the same static archives the
GitHub Release and npm ship -- nothing is recompiled here.
"""

from __future__ import annotations

import base64
import hashlib
import io
import stat
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import NoReturn

HERE = Path(__file__).resolve().parent

# Rust target triple -> the wheel platform tags it satisfies. The Linux
# binaries are static musl, so they run on both glibc (manylinux) and musl
# (musllinux) hosts; each is tagged for both so pip matches it either way.
TARGETS = [
    {"triple": "aarch64-apple-darwin", "tags": ["macosx_11_0_arm64"], "windows": False},
    {"triple": "x86_64-apple-darwin", "tags": ["macosx_10_12_x86_64"], "windows": False},
    {
        "triple": "aarch64-unknown-linux-musl",
        "tags": ["manylinux2014_aarch64", "musllinux_1_1_aarch64"],
        "windows": False,
    },
    {
        "triple": "x86_64-unknown-linux-musl",
        "tags": ["manylinux2014_x86_64", "musllinux_1_1_x86_64"],
        "windows": False,
    },
    {"triple": "x86_64-pc-windows-msvc", "tags": ["win_amd64"], "windows": True},
]


def die(msg: str) -> NoReturn:
    sys.exit(f"build: {msg}")


def read_binary(dist_dir: Path, triple: str, windows: bool) -> bytes:
    """Pull the vex-mcp binary out of a release archive without unpacking to disk."""
    bin_name = "vex-mcp.exe" if windows else "vex-mcp"
    if windows:
        archive = dist_dir / f"vex-mcp-{triple}.zip"
        if not archive.exists():
            die(f"missing archive: {archive}")
        with zipfile.ZipFile(archive) as z:
            return z.read(bin_name)
    archive = dist_dir / f"vex-mcp-{triple}.tar.gz"
    if not archive.exists():
        die(f"missing archive: {archive}")
    with tarfile.open(archive, "r:gz") as t:
        member = t.extractfile(bin_name)
        if member is None:
            die(f"{bin_name} not found in {archive}")
        return member.read()


def metadata_text(meta: dict, version: str, readme: str) -> str:
    """Render the wheel's dist-info/METADATA (Core Metadata 2.1)."""
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {meta['name']}",
        f"Version: {version}",
        f"Summary: {meta['description']}",
        f"License: {meta['license']}",
        f"Requires-Python: {meta['requires-python']}",
        "Description-Content-Type: text/markdown",
    ]
    for author in meta.get("authors", []):
        if "name" in author:
            lines.append(f"Author: {author['name']}")
        if "email" in author:
            lines.append(f"Author-email: {author['email']}")
    if keywords := meta.get("keywords"):
        lines.append("Keywords: " + ",".join(keywords))
    for label, url in meta.get("urls", {}).items():
        lines.append(f"Project-URL: {label}, {url}")
    for classifier in meta.get("classifiers", []):
        lines.append(f"Classifier: {classifier}")
    # The long description is the message body, after a blank line.
    return "\n".join(lines) + "\n\n" + readme


def wheel_text(tag: str) -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: vex-pypi-build (1.0)\n"
        "Root-Is-Purelib: false\n"
        f"Tag: py3-none-{tag}\n"
    )


def build_wheel(
    out_dir: Path,
    meta: dict,
    version: str,
    readme: str,
    binary: bytes,
    bin_name: str,
    tag: str,
) -> None:
    dist = meta["name"].replace("-", "_")
    dist_info = f"{dist}-{version}.dist-info"
    scripts = f"{dist}-{version}.data/scripts"

    records: list[str] = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

        def add(arcname: str, data: bytes, mode: int = 0o644) -> None:
            info = zipfile.ZipInfo(arcname)
            # Encode the full POSIX mode (regular-file bits + perms) in the high
            # 16 bits, so pip recognizes the binary as an executable regular file
            # and installs it with the +x bit set.
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            records.append(f"{arcname},sha256={digest},{len(data)}")

        add(f"{scripts}/{bin_name}", binary, mode=0o755)
        add(f"{dist_info}/METADATA", metadata_text(meta, version, readme).encode())
        add(f"{dist_info}/WHEEL", wheel_text(tag).encode())

        # RECORD lists every file; its own line carries no hash or size.
        records.append(f"{dist_info}/RECORD,,")
        record_info = zipfile.ZipInfo(f"{dist_info}/RECORD")
        record_info.external_attr = (stat.S_IFREG | 0o644) << 16
        record_info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(record_info, ("\n".join(records) + "\n").encode())

    fname = f"{dist}-{version}-py3-none-{tag}.whl"
    (out_dir / fname).write_bytes(buf.getvalue())
    print(f"wrote {fname}")


def main() -> None:
    if len(sys.argv) < 3:
        die("usage: python pypi/build.py <version> <dist-dir> [out-dir]")
    version = sys.argv[1]
    dist_dir = Path(sys.argv[2])
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else HERE / "dist"
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(HERE / "pyproject.toml", "rb") as f:
        meta = tomllib.load(f)["project"]
    readme = (HERE / "README.md").read_text(encoding="utf-8")

    count = 0
    for t in TARGETS:
        bin_name = "vex-mcp.exe" if t["windows"] else "vex-mcp"
        binary = read_binary(dist_dir, t["triple"], t["windows"])
        for tag in t["tags"]:
            build_wheel(out_dir, meta, version, readme, binary, bin_name, tag)
            count += 1

    print(f"\n{count} wheels in {out_dir}")


if __name__ == "__main__":
    main()
