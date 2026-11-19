"""Cryptographic constant, lookup table, and magic signature scanner."""

from __future__ import annotations

import struct
import zlib
from typing import Any

from revtool.utils import MAGIC_SIGNATURES


# First 16 bytes of AES S-Box and Inverse S-Box
AES_SBOX_HEAD = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
])
AES_INV_SBOX_HEAD = bytes([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
])

# SHA-256 initial hash values (H0..H3) and first 4 K constants
SHA256_H_LE = struct.pack("<4I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)
SHA256_H_BE = struct.pack(">4I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)
SHA256_K_LE = struct.pack("<4I", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)
SHA256_K_BE = struct.pack(">4I", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)

# MD5 initial state and first 4 sine table constants
MD5_IV_LE = struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
MD5_T_LE = struct.pack("<4I", 0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE)

# SHA-1 initial state (H0..H4)
SHA1_IV_LE = struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
SHA1_IV_BE = struct.pack(">5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

# CRC32 standard reflected table start (0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)
CRC32_TABLE_LE = struct.pack("<4I", 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)
CRC32_POLY_LE = struct.pack("<I", 0xEDB88320)

# TEA / XTEA magic delta 0x9E3779B9
TEA_DELTA_LE = struct.pack("<I", 0x9E3779B9)
TEA_DELTA_BE = struct.pack(">I", 0x9E3779B9)

# ChaCha20 / Salsa20 sigma constant
CHACHA_SIGMA = b"expand 32-byte k"
CHACHA_TAU = b"expand 16-byte k"

# Encoding alphabets
BASE64_STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_URL = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
BASE32_STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE58_BTC = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Rijndael / AES Te0 first 16 bytes (LE)
AES_TE0_LE = struct.pack("<4I", 0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6)

# SHA-512 initial H0..H1 (64-bit)
SHA512_H_LE = struct.pack("<2Q", 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B)
SHA512_H_BE = struct.pack(">2Q", 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B)

# Blowfish P-array start (Pi fractional digits)
BLOWFISH_P_LE = struct.pack("<4I", 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)

# SipHash magic constant "somepseudorandom"
SIPHASH_CONST = b"somepseudorandom"

CRYPTO_SIGNATURES: list[tuple[bytes, str, str]] = [
    (AES_SBOX_HEAD, "AES S-Box", "Symmetric Cipher (AES / Rijndael)"),
    (AES_INV_SBOX_HEAD, "AES Inverse S-Box", "Symmetric Cipher (AES Decryption)"),
    (AES_TE0_LE, "AES T-Table (Te0)", "Fast Table-Based AES"),
    (SHA256_K_LE, "SHA-256 Round Constants (LE)", "Hash (SHA-256)"),
    (SHA256_K_BE, "SHA-256 Round Constants (BE)", "Hash (SHA-256)"),
    (SHA256_H_LE, "SHA-256 Init Vector (LE)", "Hash (SHA-256)"),
    (SHA256_H_BE, "SHA-256 Init Vector (BE)", "Hash (SHA-256)"),
    (SHA512_H_LE, "SHA-512 Init Vector (LE)", "Hash (SHA-512)"),
    (SHA512_H_BE, "SHA-512 Init Vector (BE)", "Hash (SHA-512)"),
    (MD5_T_LE, "MD5 Sine Table (LE)", "Hash (MD5)"),
    (MD5_IV_LE, "MD5 Init Vector (LE)", "Hash (MD5)"),
    (SHA1_IV_LE, "SHA-1 Init Vector (LE)", "Hash (SHA-1)"),
    (SHA1_IV_BE, "SHA-1 Init Vector (BE)", "Hash (SHA-1)"),
    (CRC32_TABLE_LE, "CRC32 Lookup Table (LE)", "Checksum (CRC32)"),
    (TEA_DELTA_LE, "TEA/XTEA Delta 0x9e3779b9 (LE)", "Block Cipher (TEA / XTEA / XXTEA)"),
    (TEA_DELTA_BE, "TEA/XTEA Delta 0x9e3779b9 (BE)", "Block Cipher (TEA / XTEA / XXTEA)"),
    (BLOWFISH_P_LE, "Blowfish P-Array (LE)", "Block Cipher (Blowfish)"),
    (CHACHA_SIGMA, "ChaCha20/Salsa20 Sigma", "Stream Cipher (ChaCha20 / Salsa20)"),
    (CHACHA_TAU, "ChaCha20/Salsa20 Tau", "Stream Cipher (128-bit key)"),
    (SIPHASH_CONST, "SipHash Initialization String", "PRF / Hash (SipHash)"),
    (BASE64_STD, "Base64 Standard Alphabet", "Encoding (Base64)"),
    (BASE64_URL, "Base64 URL-Safe Alphabet", "Encoding (Base64URL)"),
    (BASE32_STD, "Base32 Alphabet", "Encoding (Base32)"),
    (BASE58_BTC, "Base58 Bitcoin Alphabet", "Encoding (Base58)"),
]


def map_offset_to_section(
    offset: int,
    sections: list[dict[str, Any]],
    image_base: int = 0,
    fmt: str = "ELF",
) -> tuple[str, int | None]:
    """Map a raw file offset to (section_name, virtual_address)."""
    for sec in sections:
        s_off = int(sec.get("offset", 0))
        s_size = int(sec.get("size", 0))
        if s_size > 0 and s_off <= offset < s_off + s_size:
            s_addr = int(sec.get("addr", 0))
            if s_addr:
                vaddr = s_addr + (offset - s_off) + (image_base if fmt == "PE" else 0)
            else:
                vaddr = None
            return (str(sec.get("name") or "<unnamed>"), vaddr)
    return ("<unmapped>", None)


CRYPTO_SPAN_SIZES: dict[str, int] = {
    "AES S-Box": 256,
    "AES Inverse S-Box": 256,
    "AES T-Table (Te0)": 1024,
    "CRC32 Lookup Table (LE)": 1024,
    "SHA-256 Round Constants (LE)": 256,
    "SHA-256 Round Constants (BE)": 256,
    "MD5 Sine Table (LE)": 256,
}


def scan_crypto_constants(
    data: bytes,
    sections: list[dict[str, Any]] | None = None,
    image_base: int = 0,
    fmt: str = "ELF",
) -> list[dict[str, Any]]:
    """Scan binary data for known cryptographic constants and encoding tables."""
    sections = sections or []
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    for pattern, name, category in CRYPTO_SIGNATURES:
        start = 0
        hits = 0
        span = CRYPTO_SPAN_SIZES.get(name, len(pattern))
        while hits < 8:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            if (name, idx) not in seen:
                seen.add((name, idx))
                sec_name, vaddr = map_offset_to_section(idx, sections, image_base, fmt)
                findings.append(
                    {
                        "name": name,
                        "category": category,
                        "offset": idx,
                        "size": span,
                        "vaddr": vaddr,
                        "section": sec_name,
                    }
                )
            start = idx + len(pattern)
            hits += 1

    findings.sort(key=lambda x: x["offset"])
    return findings


_NON_PAYLOAD_SECTIONS = {
    ".text", ".init", ".fini", ".plt", ".plt.got", ".plt.sec",
    ".pdata", ".xdata", ".eh_frame", ".eh_frame_hdr",
    ".reloc", ".gnu.hash", ".dynsym", ".symtab", ".strtab", ".dynstr",
}


def _is_valid_zlib_stream(chunk: bytes) -> bool:
    """Validate that a candidate 0x78 0x9c/0xda offset actually decompresses cleanly."""
    if len(chunk) < 8:
        return False
    # Zlib RFC 1950 header check: (CMF * 256 + FLG) % 31 == 0
    if ((chunk[0] << 8) | chunk[1]) % 31 != 0:
        return False
    try:
        decomp = zlib.decompressobj()
        out = decomp.decompress(chunk[:1024], 256)
        return len(out) >= 16 or (decomp.eof and len(out) >= 8)
    except zlib.error:
        return False


def scan_embedded_magic(
    data: bytes,
    sections: list[dict[str, Any]] | None = None,
    image_base: int = 0,
    fmt: str = "ELF",
    max_hits: int = 40,
) -> list[dict[str, Any]]:
    """Scan binary for embedded file signatures (ignoring offset 0 and tiny 2-byte MZ false positives)."""
    sections = sections or []
    hits: list[dict[str, Any]] = []

    # Skip very short/noisy 2-3 byte signatures when scanning mid-file unless strong
    strong_sigs = [
        (sig, tag, desc)
        for sig, tag, desc in MAGIC_SIGNATURES
        if len(sig) >= 4
    ]
    # Also scan Zlib streams (common in packed CTFs / PNGs / PyInstaller)
    zlib_headers = [
        (b"\x78\x9c", "ZLIB", "Zlib Compressed Stream (default compression)"),
        (b"\x78\xda", "ZLIB", "Zlib Compressed Stream (best compression)"),
    ]

    for sig, tag, desc in strong_sigs:
        pos = 1  # skip offset 0 (the outer file itself)
        count = 0
        while count < 5 and len(hits) < max_hits:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            sec_name, vaddr = map_offset_to_section(idx, sections, image_base, fmt)
            hits.append(
                {
                    "type": tag,
                    "description": desc,
                    "offset": idx,
                    "vaddr": vaddr,
                    "section": sec_name,
                }
            )
            pos = idx + len(sig)
            count += 1

    # Validate Zlib streams and skip metadata/unwind sections (.pdata, .eh_frame, etc.)
    for sig, tag, desc in zlib_headers:
        pos = 1
        count = 0
        while count < 4 and len(hits) < max_hits:
            idx = data.find(sig, pos)
            if idx == -1:
                break
            sec_name, vaddr = map_offset_to_section(idx, sections, image_base, fmt)
            if sec_name not in _NON_PAYLOAD_SECTIONS and _is_valid_zlib_stream(data[idx : idx + 1024]):
                hits.append(
                    {
                        "type": tag,
                        "description": desc,
                        "offset": idx,
                        "vaddr": vaddr,
                        "section": sec_name,
                    }
                )
                count += 1
            pos = idx + 2

    hits.sort(key=lambda x: x["offset"])
    return hits[:max_hits]
