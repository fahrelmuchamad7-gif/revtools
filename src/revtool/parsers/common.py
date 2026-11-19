"""Unified binary analysis entry point dispatching to format-specific parsers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from revtool.parsers.elf import parse_elf
from revtool.parsers.gopclntab import parse_gopclntab
from revtool.parsers.macho import parse_macho
from revtool.parsers.pe import parse_pe
from revtool.utils import (
    calculate_entropy,
    calculate_hashes,
    detect_magic,
    detect_packer_hints,
    format_size,
)


def analyze_file(file_path: str | Path) -> dict[str, Any]:
    """Read and statically inspect a binary file, returning a structured report."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Path is not a regular file: {path}")

    data = path.read_bytes()
    fmt, magic_desc = detect_magic(data)
    overall_entropy = calculate_entropy(data)
    hashes = calculate_hashes(data)

    report: dict[str, Any] = {
        "file": {
            "path": str(path),
            "name": path.name,
            "size_bytes": len(data),
            "size_human": format_size(len(data)),
            "format": fmt,
            "magic_description": magic_desc,
            "entropy": overall_entropy,
            "hashes": hashes,
        },
        "format": fmt,
        "header": {},
        "mitigations": {},
        "init_functions": [],
        "plt_map": {},
        "tls_callbacks": [],
        "segments": [],
        "sections": [],
        "needed_libraries": [],
        "imports": [],
        "imported_symbols": [],
        "symbols": [],
        "exports": [],
        "hints": [],
        "warnings": [],
    }

    parsed: dict[str, Any] | None = None
    if fmt == "ELF":
        parsed = parse_elf(data)
    elif fmt == "PE":
        parsed = parse_pe(data)
    elif fmt == "MACH-O":
        parsed = parse_macho(data)

    if parsed is not None:
        if "error" in parsed:
            report["warnings"].append(parsed["error"])
        else:
            for key in (
                "format",
                "header",
                "mitigations",
                "init_functions",
                "plt_map",
                "tls_callbacks",
                "segments",
                "sections",
                "needed_libraries",
                "imports",
                "imported_symbols",
                "symbols",
                "exports",
                "warnings",
            ):
                if key in parsed:
                    report[key] = parsed[key]

    if fmt in ("ELF", "PE", "MACH-O") and (
        any(str(s.get("name", "")).lower() in (".gopclntab", "__gopclntab") for s in report["sections"])
        or b"Go build ID:" in data
        or b"runtime.main" in data
    ):
        go_syms = parse_gopclntab(data, report["sections"])
        if go_syms:
            existing = {s["name"] for s in report["symbols"]}
            merged = [s for s in go_syms if s["name"] not in existing]
            report["symbols"] = merged + report["symbols"]

    report["hints"] = detect_packer_hints(report["sections"], overall_entropy)
    return report
