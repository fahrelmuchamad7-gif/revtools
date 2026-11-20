"""Context-aware ASCII and UTF-16LE string extractor with CTF recon tagging."""

from __future__ import annotations

import re
from typing import Any

from revtool.crypto_scan import map_offset_to_section


_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_FLAG_RE = re.compile(r"(?:flag|ctf|cj|cyb\d*|gemastik|compfest|arkav|findit|picoctf|htb)\{[^}]{2,}\}", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_B64_RE = re.compile(r"^(?:[A-Za-z0-9+/]{16,}={0,2})$")
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{16,}$")

_CRYPTO_WORDS = (
    "aes", "rsa", "rc4", "chacha", "salsa", "sha256", "sha1", "md5",
    "decrypt", "encrypt", "cipher", "xor", "sbox", "pkcs", "hmac", "salt",
)
_ANTIDBG_WORDS = (
    "ptrace", "debugger", "tracerpid", "/proc/self/status", "isdebuggerpresent",
    "sigsegv", "sigill", "sigtrap", "rdtsc", "ld_preload", "frida", "xposed",
)
_EXEC_WORDS = (
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "mmap", "mprotect",
    "memfd_create", "virtualalloc", "virtualprotect", "execve",
)
_CRACKME_WORDS = (
    "correct", "incorrect", "wrong flag", "success", "failure",
    "flaginput", "validatebtn", "checkflag", "congrats", "evalnwbin",
)
_SECRET_WORDS = (
    "secret", "api_key", "apikey", "bearer ", "token", "private_key",
    "rules.json", "traffic.pcap",
)


def classify_string(text: str) -> list[str]:
    """Assign high-signal recon tags to an extracted string."""
    tags: list[str] = []
    lower = text.lower()

    if _FLAG_RE.search(text):
        tags.append("FLAG_FMT")
    if _URL_RE.search(text):
        tags.append("URL")
    if _IP_RE.search(text):
        tags.append("IP")
    if len(text) >= 16 and _HEX_RE.match(text):
        tags.append("HEX_BLOB")
    elif len(text) >= 20 and len(text) % 4 == 0 and _B64_RE.match(text):
        # Avoid tagging Go/Unix package paths like `internal/reflectlite` or plain identifiers
        has_eq_pad = text.endswith("=")
        has_upper = any(c.isupper() for c in text)
        has_lower = any(c.islower() for c in text)
        has_digit = any(c.isdigit() for c in text)
        looks_like_pkg_path = "/" in text and not has_eq_pad and not any(c.isdigit() for c in text)
        if not looks_like_pkg_path and (
            has_eq_pad or ("+" in text and has_upper and has_lower) or (has_upper and has_lower and has_digit)
        ):
            tags.append("BASE64_CAND")
    if any(w in lower for w in _CRYPTO_WORDS):
        tags.append("CRYPTO")
    if any(w in lower for w in _ANTIDBG_WORDS):
        tags.append("ANTI_DBG")
    if any(w in lower for w in _EXEC_WORDS):
        tags.append("EXEC_IO")
    if any(w in lower for w in _CRACKME_WORDS):
        tags.append("CRACKME_UI")
    if any(w in lower for w in _SECRET_WORDS):
        tags.append("SECRET")
    if text.startswith("_D") and len(text) >= 5 and text[2].isdigit():
        tags.append("DLANG_SYM")
    if ("/" in text or "\\" in text) and len(text) >= 5 and not _URL_RE.search(text):
        if text.startswith(("/", "./", "../", "C:\\", "\\\\")) or "/proc/" in text or "/dev/" in text:
            tags.append("PATH")

    return tags


def extract_strings(
    data: bytes,
    sections: list[dict[str, Any]] | None = None,
    image_base: int = 0,
    fmt: str = "ELF",
    min_len: int = 5,
    encoding: str = "both",
    regex_filter: str | None = None,
    tag_filter: str | None = None,
    section_filter: str | None = None,
    only_interesting: bool = False,
) -> list[dict[str, Any]]:
    """Extract ASCII and/or UTF-16LE strings with section mapping and recon tags."""
    sections = sections or []
    compiled_re = re.compile(regex_filter, re.I) if regex_filter else None
    tag_upper = tag_filter.upper() if tag_filter else None
    sec_lower = section_filter.lower() if section_filter else None

    results: list[dict[str, Any]] = []

    if encoding in ("ascii", "both"):
        for m in _ASCII_RE.finditer(data):
            if len(m.group()) < min_len:
                continue
            text = m.group().decode("ascii", errors="replace")
            off = m.start()
            sec_name, vaddr = map_offset_to_section(off, sections, image_base, fmt)
            tags = classify_string(text)
            if only_interesting and not tags:
                continue
            if tag_upper and tag_upper not in tags:
                continue
            if sec_lower and sec_lower not in sec_name.lower():
                continue
            if compiled_re and not compiled_re.search(text):
                continue
            results.append(
                {
                    "offset": off,
                    "vaddr": vaddr,
                    "section": sec_name,
                    "encoding": "ascii",
                    "tags": tags,
                    "value": text,
                }
            )

    if encoding in ("utf16", "both"):
        for m in _UTF16LE_RE.finditer(data):
            char_len = len(m.group()) // 2
            if char_len < min_len:
                continue
            text = m.group().decode("utf-16-le", errors="replace")
            off = m.start()
            sec_name, vaddr = map_offset_to_section(off, sections, image_base, fmt)
            tags = classify_string(text)
            if only_interesting and not tags:
                continue
            if tag_upper and tag_upper not in tags:
                continue
            if sec_lower and sec_lower not in sec_name.lower():
                continue
            if compiled_re and not compiled_re.search(text):
                continue
            results.append(
                {
                    "offset": off,
                    "vaddr": vaddr,
                    "section": sec_name,
                    "encoding": "utf16le",
                    "tags": tags,
                    "value": text,
                }
            )

    results.sort(key=lambda x: x["offset"])
    return results
