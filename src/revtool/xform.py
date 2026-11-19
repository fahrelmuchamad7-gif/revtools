"""Static byte slice and transform helper (ROL/ROR, XOR, Base64, Hex, Endian swap)."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from revtool.parsers import analyze_file
from revtool.utils import calculate_entropy, detect_magic


def _parse_key(raw: str) -> bytes:
    """Parse key from `hex:...` / `0x...` or UTF-8 text."""
    if raw.startswith("hex:"):
        return bytes.fromhex(raw[4:].replace(" ", ""))
    if raw.startswith("0x") and len(raw) > 2:
        hx = raw[2:]
        if len(hx) % 2 == 1:
            hx = "0" + hx
        return bytes.fromhex(hx)
    return raw.encode("utf-8")


def rotate_words(data: bytes, bits: int, word_size: int = 4, left: bool = True) -> bytes:
    """Rotate each little-endian word of size `word_size` (1, 2, 4, 8) by `bits`."""
    if word_size not in (1, 2, 4, 8):
        raise ValueError("word_size must be one of 1, 2, 4, 8.")
    mask = (1 << (word_size * 8)) - 1
    shift = bits % (word_size * 8)
    out = bytearray()
    for i in range(0, len(data), word_size):
        chunk = data[i : i + word_size]
        if len(chunk) < word_size:
            out.extend(chunk)
            continue
        val = int.from_bytes(chunk, "little")
        if left:
            rot = ((val << shift) | (val >> (word_size * 8 - shift))) & mask
        else:
            rot = ((val >> shift) | (val << (word_size * 8 - shift))) & mask
        out.extend(rot.to_bytes(word_size, "little"))
    return bytes(out)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with repeating byte key."""
    if not key:
        raise ValueError("XOR key cannot be empty.")
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def reverse_words(data: bytes, word_size: int = 4) -> bytes:
    """Swap byte order (endianness) per word_size chunk."""
    if word_size <= 1:
        return data[::-1]
    out = bytearray()
    for i in range(0, len(data), word_size):
        out.extend(data[i : i + word_size][::-1])
    return bytes(out)


def transform_slice(
    file_path: str | Path,
    section_name: str | None = None,
    offset: int = 0,
    length: int | None = None,
    rol_bits: int | None = None,
    ror_bits: int | None = None,
    word_size: int = 4,
    xor_key: str | None = None,
    swap_endian: bool = False,
    from_hex: bool = False,
    from_b64: bool = False,
    out_file: str | Path | None = None,
) -> dict[str, Any]:
    """Extract a byte slice and apply requested static transforms."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    raw = path.read_bytes()
    start = offset
    end = len(raw) if length is None else min(len(raw), offset + length)

    if section_name:
        report = analyze_file(path)
        matched = [s for s in report.get("sections", []) if s.get("name") == section_name]
        if not matched:
            raise ValueError(f"Section '{section_name}' not found.")
        sec = matched[0]
        start = int(sec["offset"]) + offset
        sec_end = int(sec["offset"]) + int(sec["size"])
        end = sec_end if length is None else min(sec_end, start + length)

    if start < 0 or start >= len(raw):
        raise ValueError(f"Offset 0x{start:x} out of range for file size {len(raw)}.")

    buf = raw[start:end]
    steps: list[str] = [f"slice[0x{start:x}:0x{end:x}] ({len(buf)} B)"]

    if swap_endian:
        buf = reverse_words(buf, word_size=word_size)
        steps.append(f"endian-swap({word_size}B)")
    if rol_bits is not None:
        buf = rotate_words(buf, rol_bits, word_size=word_size, left=True)
        steps.append(f"rol({rol_bits}, {word_size}B)")
    if ror_bits is not None:
        buf = rotate_words(buf, ror_bits, word_size=word_size, left=False)
        steps.append(f"ror({ror_bits}, {word_size}B)")
    if xor_key is not None:
        key_bytes = _parse_key(xor_key)
        buf = xor_bytes(buf, key_bytes)
        steps.append(f"xor({xor_key})")
    if from_hex:
        cleaned = b"".join(buf.split())
        buf = bytes.fromhex(cleaned.decode("ascii"))
        steps.append("unhex")
    if from_b64:
        buf = base64.b64decode(buf, validate=False)
        steps.append("b64decode")

    if out_file is not None:
        Path(out_file).write_bytes(buf)

    fmt, desc = detect_magic(buf)
    printable_preview = "".join(
        chr(b) if 32 <= b <= 126 else ("." if b not in (10, 13, 9) else " ")
        for b in buf[:256]
    )

    return {
        "input_file": str(path),
        "pipeline": " -> ".join(steps),
        "output_size": len(buf),
        "detected_format": fmt,
        "detected_description": desc,
        "entropy": calculate_entropy(buf),
        "preview_hex": buf[:64].hex(" "),
        "preview_ascii": printable_preview,
        "written_to": str(out_file) if out_file else None,
    }
