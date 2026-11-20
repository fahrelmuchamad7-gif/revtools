"""Common utility helpers for hashing, entropy, magic detection, and formatting."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from typing import Any


MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\x7fELF", "ELF", "ELF Executable / Shared Object"),
    (b"MZ", "PE", "DOS / Windows PE Executable"),
    (b"\xfe\xed\xfa\xce", "MACH-O", "Mach-O 32-bit (Big Endian)"),
    (b"\xce\xfa\xed\xfe", "MACH-O", "Mach-O 32-bit (Little Endian)"),
    (b"\xfe\xed\xfa\xcf", "MACH-O", "Mach-O 64-bit (Big Endian)"),
    (b"\xcf\xfa\xed\xfe", "MACH-O", "Mach-O 64-bit (Little Endian)"),
    (b"\xca\xfe\xba\xbe", "FAT/CLASS", "Mach-O Fat Binary or Java Class"),
    (b"\x00asm", "WASM", "WebAssembly Binary"),
    (b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f", "HERMES", "React Native Hermes Bytecode (HBC)"),
    (b"\x1f\x19\x03\xc1", "HERMES", "React Native Hermes Bytecode (HBC)"),
    (b"\x89\x06\xde\xc0", "V8_CACHE", "V8 Bytecode Cache / NW.js Snapshot (nwjc)"),
    (b"\xc0\xde\x06\x89", "V8_CACHE", "V8 Bytecode Cache / NW.js Snapshot (nwjc)"),
    (b"PK\x03\x04", "ZIP", "ZIP Archive (or JAR/APK/DOCX)"),
    (b"\x1f\x8b\x08", "GZIP", "GZIP Compressed Data"),
    (b"BZh", "BZIP2", "BZIP2 Compressed Data"),
    (b"\xfd7zXZ\x00", "XZ", "XZ Compressed Data"),
    (b"7z\xbc\xaf\x27\x1c", "7Z", "7-Zip Archive"),
    (b"\x28\xb5\x2f\xfd", "ZSTD", "Zstandard Compressed Data"),
    (b"%PDF-", "PDF", "PDF Document"),
    (b"\x89PNG\r\n\x1a\n", "PNG", "PNG Image"),
    (b"\xff\xd8\xff", "JPEG", "JPEG Image"),
    (b"GIF87a", "GIF", "GIF87a Image"),
    (b"GIF89a", "GIF", "GIF89a Image"),
    (b"SQLite format 3\x00", "SQLITE", "SQLite 3 Database"),
    (b"!<arch>\n", "AR", "Unix Static Archive (.a / .deb)"),
    (b"dex\n", "DEX", "Android Dalvik Executable (DEX)"),
]

KNOWN_PACKER_SECTIONS: dict[str, str] = {
    "upx0": "UPX packer",
    "upx1": "UPX packer",
    "upx2": "UPX packer",
    ".aspack": "ASPack packer",
    ".adata": "ASPack packer",
    ".mpress1": "MPRESS packer",
    ".mpress2": "MPRESS packer",
    ".themida": "Themida/WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".enigma1": "Enigma Protector",
    ".nsp0": "NsPack",
    ".petite": "Petite packer",
    "mew": "MEW packer",
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) of a byte sequence."""
    length = len(data)
    if length == 0:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_hashes(data: bytes) -> dict[str, str]:
    """Return MD5, SHA-1, and SHA-256 hex digests."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def format_size(num_bytes: int) -> str:
    """Format byte count as human-readable size."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    units = ["KiB", "MiB", "GiB", "TiB"]
    size = float(num_bytes)
    for unit in units:
        size /= 1024.0
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.2f} {unit} ({num_bytes:,} B)"
    return f"{num_bytes} B"


def read_cstr(data: bytes, offset: int, max_len: int = 512) -> str:
    """Read a null-terminated ASCII/UTF-8 string from bytes at offset."""
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("utf-8", errors="replace")


def detect_magic(data: bytes) -> tuple[str, str]:
    """Detect basic file format from magic bytes."""
    if not data:
        return ("EMPTY", "Empty File")

    # Check standard signatures
    for sig, fmt, desc in MAGIC_SIGNATURES:
        if data.startswith(sig):
            if fmt == "FAT/CLASS" and len(data) >= 8:
                # Java class files have minor/major version (e.g. major >= 45),
                # while Mach-O Fat has small nfat_arch (< 32)
                nfat = int.from_bytes(data[4:8], "big")
                if nfat <= 32:
                    return ("MACH-O", f"Mach-O Universal/Fat Binary ({nfat} archs)")
                return ("JAVA", "Java Compiled Class (.class)")
            return (fmt, desc)

    # Check script shebang
    if data.startswith(b"#!"):
        first_line = data.splitlines()[0].decode("utf-8", errors="replace").strip()
        return ("SCRIPT", f"Executable Script ({first_line})")

    # Check if mostly printable text
    sample = data[:1024]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    if sample and (printable / len(sample)) > 0.90:
        return ("TEXT", "Plain Text / Source File")

    return ("UNKNOWN", "Unknown / Raw Binary Data")


def detect_packer_hints(
    sections: list[dict[str, Any]],
    overall_entropy: float,
) -> list[str]:
    """Identify common static hints of packing, compression, or obfuscation."""
    hints: list[str] = []
    seen: set[str] = set()

    for sec in sections:
        name = str(sec.get("name", "")).strip()
        lower = name.lower()
        if lower in KNOWN_PACKER_SECTIONS:
            label = f"Section '{name}' matches {KNOWN_PACKER_SECTIONS[lower]}"
            if label not in seen:
                seen.add(label)
                hints.append(label)

        sec_entropy = float(sec.get("entropy", 0.0))
        sec_size = int(sec.get("size", 0))
        sec_perms = str(sec.get("perms", ""))
        if sec_size >= 256 and sec_entropy >= 7.2:
            hints.append(
                f"High entropy ({sec_entropy:.2f}) in section '{name or '<unnamed>'}' "
                "(possibly packed, compressed, or encrypted)"
            )
        if "W" in sec_perms and "X" in sec_perms:
            hints.append(
                f"Section '{name or '<unnamed>'}' is both Writable and Executable (WX)"
            )

    if overall_entropy >= 7.2 and not any("High entropy" in h for h in hints):
        hints.append(
            f"High overall file entropy ({overall_entropy:.2f}) "
            "(possibly packed or compressed)"
        )

    return hints
