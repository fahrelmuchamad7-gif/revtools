"""Pure-Python Go gopclntab parser for recovering Go function names and addresses."""

from __future__ import annotations

import struct
from typing import Any

from revtool.utils import read_cstr


# Go pclntab magics (little-endian uint32):
# 0xFFFFFFF1 -> Go 1.20+
# 0xFFFFFFF0 -> Go 1.18 - 1.19
# 0xFFFFFFFA -> Go 1.16 - 1.17
# 0xFFFFFFFB -> Go 1.2 - 1.15
GO_MAGIC_120 = b"\xf1\xff\xff\xff\x00\x00"
GO_MAGIC_118 = b"\xf0\xff\xff\xff\x00\x00"
GO_MAGIC_116 = b"\xfa\xff\xff\xff\x00\x00"
GO_MAGIC_102 = b"\xfb\xff\xff\xff\x00\x00"


def _find_gopclntab_offset(data: bytes, sections: list[dict[str, Any]]) -> int | None:
    """Locate the start of gopclntab in ELF/PE sections or raw binary data."""
    for sec in sections:
        name = str(sec.get("name", "")).lower()
        if name in (".gopclntab", "__gopclntab"):
            off = int(sec.get("offset", 0))
            if 0 <= off < len(data):
                return off

    for magic in (GO_MAGIC_120, GO_MAGIC_118, GO_MAGIC_116, GO_MAGIC_102):
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            if idx + 16 <= len(data):
                min_lc = data[idx + 6]
                ptr_sz = data[idx + 7]
                if min_lc in (1, 2, 4) and ptr_sz in (4, 8):
                    return idx
            pos = idx + 4
    return None


def parse_gopclntab(
    data: bytes,
    sections: list[dict[str, Any]] | None = None,
    max_funcs: int = 200000,
) -> list[dict[str, Any]]:
    """Extract Go function symbols from gopclntab (supports Go 1.2 through Go 1.25+)."""
    sections = sections or []
    base = _find_gopclntab_offset(data, sections)
    if base is None or base + 16 > len(data):
        return []

    magic = struct.unpack_from("<I", data, base)[0]
    min_lc = data[base + 6]
    ptr_sz = data[base + 7]
    if min_lc not in (1, 2, 4) or ptr_sz not in (4, 8):
        return []

    pfmt = "<Q" if ptr_sz == 8 else "<I"
    symbols: list[dict[str, Any]] = []

    if magic in (0xFFFFFFF1, 0xFFFFFFF0):
        # Header: magic(4) pad(2) minLC(1) ptrSize(1) + 8 ptr-sized fields
        if base + 8 + 8 * ptr_sz > len(data):
            return []
        fields = struct.unpack_from(f"<{8}{'Q' if ptr_sz == 8 else 'I'}", data, base + 8)
        nfunc, _nfiles, text_start, funcname_off, _cu_off, _filetab_off, _pctab_off, pcln_off = fields

        ftab_start = base + pcln_off
        funcname_start = base + funcname_off
        if nfunc == 0 or nfunc > 500000 or ftab_start >= len(data) or funcname_start >= len(data):
            return []

        count = min(nfunc, max_funcs)
        for i in range(count):
            ent_pos = ftab_start + i * 8
            if ent_pos + 8 > len(data):
                break
            entry_off, func_off = struct.unpack_from("<II", data, ent_pos)
            vaddr = text_start + entry_off

            func_struct_pos = ftab_start + func_off
            if func_struct_pos + 8 > len(data):
                continue
            _f_entry_off, name_off = struct.unpack_from("<Ii", data, func_struct_pos)
            if name_off < 0 or funcname_start + name_off >= len(data):
                continue
            name = read_cstr(data, funcname_start + name_off, max_len=256)
            if not name:
                continue

            # Estimate function size from next entry in ftab when available
            size = 0
            if ent_pos + 16 <= len(data):
                next_entry_off = struct.unpack_from("<I", data, ent_pos + 8)[0]
                if next_entry_off >= entry_off:
                    size = next_entry_off - entry_off

            symbols.append(
                {
                    "name": name,
                    "table": ".gopclntab",
                    "bind": "GO_USER" if name.startswith("main.") else "GO_PKG",
                    "type": "FUNC",
                    "value": vaddr,
                    "size": size,
                    "section": ".text",
                    "imported": False,
                }
            )

    elif magic == 0xFFFFFFFA:
        # Go 1.16 - 1.17: nfunc, nfiles, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset
        if base + 8 + 7 * ptr_sz > len(data):
            return []
        fields = struct.unpack_from(f"<{7}{'Q' if ptr_sz == 8 else 'I'}", data, base + 8)
        nfunc, _nfiles, funcname_off, _cu_off, _filetab_off, _pctab_off, pcln_off = fields
        ftab_start = base + pcln_off
        funcname_start = base + funcname_off
        if nfunc == 0 or nfunc > 500000 or ftab_start >= len(data) or funcname_start >= len(data):
            return []

        ent_sz = ptr_sz * 2
        count = min(nfunc, max_funcs)
        for i in range(count):
            ent_pos = ftab_start + i * ent_sz
            if ent_pos + ent_sz > len(data):
                break
            vaddr, func_off = struct.unpack_from(f"<{'QQ' if ptr_sz == 8 else 'II'}", data, ent_pos)
            func_struct_pos = ftab_start + func_off
            if func_struct_pos + ptr_sz + 4 > len(data):
                continue
            name_off = struct.unpack_from("<i", data, func_struct_pos + ptr_sz)[0]
            if name_off < 0 or funcname_start + name_off >= len(data):
                continue
            name = read_cstr(data, funcname_start + name_off, max_len=256)
            if not name:
                continue
            symbols.append(
                {
                    "name": name,
                    "table": ".gopclntab",
                    "bind": "GO_USER" if name.startswith("main.") else "GO_PKG",
                    "type": "FUNC",
                    "value": vaddr,
                    "size": 0,
                    "section": ".text",
                    "imported": False,
                }
            )

    elif magic == 0xFFFFFFFB:
        # Go 1.2 - 1.15: nfunc right at base + 8, followed by ftab entries (entry, funcoff)
        if base + 8 + ptr_sz > len(data):
            return []
        nfunc = struct.unpack_from(pfmt, data, base + 8)[0]
        ftab_start = base + 8 + ptr_sz
        if nfunc == 0 or nfunc > 500000 or ftab_start >= len(data):
            return []
        ent_sz = ptr_sz * 2
        count = min(nfunc, max_funcs)
        for i in range(count):
            ent_pos = ftab_start + i * ent_sz
            if ent_pos + ent_sz > len(data):
                break
            vaddr, func_off = struct.unpack_from(f"<{'QQ' if ptr_sz == 8 else 'II'}", data, ent_pos)
            func_struct_pos = base + func_off
            if func_struct_pos + ptr_sz + 4 > len(data):
                continue
            name_off = struct.unpack_from("<i", data, func_struct_pos + ptr_sz)[0]
            if name_off < 0 or base + name_off >= len(data):
                continue
            name = read_cstr(data, base + name_off, max_len=256)
            if not name:
                continue
            symbols.append(
                {
                    "name": name,
                    "table": ".gopclntab",
                    "bind": "GO_USER" if name.startswith("main.") else "GO_PKG",
                    "type": "FUNC",
                    "value": vaddr,
                    "size": 0,
                    "section": ".text",
                    "imported": False,
                }
            )

    # Sort user `main.*` functions first so `revtool symbols` surfaces them immediately
    symbols.sort(key=lambda s: (0 if s["name"].startswith("main.") else 1, s["value"]))
    return symbols
