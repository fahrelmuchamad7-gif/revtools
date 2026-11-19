"""Pure-Python PE32 and PE32+ (Windows EXE/DLL) static binary parser."""

from __future__ import annotations

import datetime
import struct
from typing import Any

from revtool.utils import calculate_entropy, read_cstr


PE_MACHINES: dict[int, str] = {
    0x0: "Unknown",
    0x14C: "x86 (i386)",
    0x1C0: "ARM",
    0x1C4: "ARMv7 Thumb-2",
    0x8664: "x86_64 (AMD64)",
    0xAA64: "AArch64 (ARM64)",
    0x200: "IA-64",
    0x5032: "RISC-V 32-bit",
    0x5064: "RISC-V 64-bit",
}

PE_SUBSYSTEMS: dict[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI (Console)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    14: "Xbox",
    16: "Windows Boot Application",
}


def _pe_section_perms(characteristics: int) -> str:
    r = "R" if (characteristics & 0x40000000) else "-"
    w = "W" if (characteristics & 0x80000000) else "-"
    x = "X" if (characteristics & 0x20000000) else "-"
    return f"{r}{w}{x}"


def _rva_to_offset(rva: int, sections: list[dict[str, Any]], file_len: int) -> int | None:
    """Convert a Relative Virtual Address (RVA) to a raw file offset."""
    if rva == 0:
        return None
    for sec in sections:
        vaddr = sec["addr"]
        vsize = max(sec["virtual_size"], sec["size"])
        raw_ptr = sec["offset"]
        raw_size = sec["size"]
        if vaddr <= rva < vaddr + vsize:
            delta = rva - vaddr
            if delta < raw_size and raw_ptr + delta < file_len:
                return raw_ptr + delta
            return None
    return None


def parse_pe(data: bytes) -> dict[str, Any]:
    """Parse PE32/PE32+ headers, sections, imports, exports, and flags."""
    warnings: list[str] = []
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"error": "Not a valid PE file (missing MZ header)."}

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return {"error": "DOS executable (MZ), but missing valid PE signature."}

    coff_off = e_lfanew + 4
    (
        machine,
        num_sections,
        timestamp,
        _ptr_symtab,
        _num_symbols,
        size_opt_header,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_off)

    opt_off = coff_off + 20
    if opt_off + 2 > len(data):
        return {"error": "Truncated PE Optional Header."}

    opt_magic = struct.unpack_from("<H", data, opt_off)[0]
    if opt_magic == 0x10B:
        pe_type = "PE32"
        bits = 32
    elif opt_magic == 0x20B:
        pe_type = "PE32+"
        bits = 64
    else:
        return {"error": f"Unsupported PE Optional Header magic: 0x{opt_magic:x}"}

    entry_point_rva = 0
    image_base = 0
    subsystem = 0
    dll_chars = 0
    data_dirs: list[tuple[int, int]] = []

    if bits == 32 and opt_off + 96 <= len(data):
        entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        dll_chars = struct.unpack_from("<H", data, opt_off + 70)[0]
        num_rva_sizes = min(struct.unpack_from("<I", data, opt_off + 92)[0], 16)
        dd_off = opt_off + 96
        for i in range(num_rva_sizes):
            if dd_off + (i + 1) * 8 <= len(data):
                data_dirs.append(struct.unpack_from("<II", data, dd_off + i * 8))
    elif bits == 64 and opt_off + 112 <= len(data):
        entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        dll_chars = struct.unpack_from("<H", data, opt_off + 70)[0]
        num_rva_sizes = min(struct.unpack_from("<I", data, opt_off + 108)[0], 16)
        dd_off = opt_off + 112
        for i in range(num_rva_sizes):
            if dd_off + (i + 1) * 8 <= len(data):
                data_dirs.append(struct.unpack_from("<II", data, dd_off + i * 8))
    else:
        warnings.append("Optional header truncated; some metadata may be missing.")

    # Parse Section Headers
    sec_table_off = opt_off + size_opt_header
    sections: list[dict[str, Any]] = []
    for i in range(num_sections):
        off = sec_table_off + i * 40
        if off + 40 > len(data):
            warnings.append("PE section header table truncated.")
            break
        (
            raw_name,
            virtual_size,
            virtual_addr,
            raw_size,
            raw_ptr,
            _ptr_reloc,
            _ptr_linenum,
            _num_reloc,
            _num_linenum,
            sec_chars,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, off)

        sec_name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        sec_entropy = 0.0
        if raw_size > 0 and raw_ptr < len(data):
            sec_bytes = data[raw_ptr : min(len(data), raw_ptr + raw_size)]
            sec_entropy = calculate_entropy(sec_bytes)

        sections.append(
            {
                "index": i,
                "name": sec_name,
                "type": "CODE" if (sec_chars & 0x20) else ("INIT_DATA" if (sec_chars & 0x40) else "DATA"),
                "addr": virtual_addr,
                "virtual_size": virtual_size,
                "offset": raw_ptr,
                "size": raw_size,
                "perms": _pe_section_perms(sec_chars),
                "entropy": sec_entropy,
            }
        )

    # Parse Import Directory (Data Directory index 1)
    imports: list[dict[str, Any]] = []
    imported_symbols: list[dict[str, Any]] = []
    if len(data_dirs) > 1:
        imp_rva, _imp_size = data_dirs[1]
        imp_off = _rva_to_offset(imp_rva, sections, len(data))
        if imp_off is not None:
            pos = imp_off
            max_descriptors = 512
            count = 0
            while pos + 20 <= len(data) and count < max_descriptors:
                orig_first_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", data, pos)
                pos += 20
                count += 1
                if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                    break
                dll_name_off = _rva_to_offset(name_rva, sections, len(data))
                dll_name = read_cstr(data, dll_name_off) if dll_name_off is not None else "<unknown>"

                thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
                thunk_off = _rva_to_offset(thunk_rva, sections, len(data))
                funcs: list[str] = []
                if thunk_off is not None:
                    entry_size = 8 if bits == 64 else 4
                    entry_fmt = "<Q" if bits == 64 else "<I"
                    ord_flag = (1 << 63) if bits == 64 else (1 << 31)
                    tpos = thunk_off
                    max_funcs = 4096
                    fcount = 0
                    while tpos + entry_size <= len(data) and fcount < max_funcs:
                        val = struct.unpack_from(entry_fmt, data, tpos)[0]
                        tpos += entry_size
                        fcount += 1
                        if val == 0:
                            break
                        if val & ord_flag:
                            fname = f"Ordinal#{val & 0xFFFF}"
                        else:
                            ibn_off = _rva_to_offset(val & 0x7FFFFFFF, sections, len(data))
                            if ibn_off is not None and ibn_off + 2 < len(data):
                                fname = read_cstr(data, ibn_off + 2)
                            else:
                                fname = f"RVA:0x{val:x}"
                        funcs.append(fname)
                        imported_symbols.append(
                            {
                                "name": fname,
                                "library": dll_name,
                                "table": "ImportTable",
                                "type": "FUNC",
                                "bind": "IMPORT",
                                "value": 0,
                                "size": 0,
                                "section": dll_name,
                                "imported": True,
                            }
                        )
                imports.append({"library": dll_name, "functions": funcs})

    # Parse Export Directory (Data Directory index 0)
    exports: list[dict[str, Any]] = []
    if len(data_dirs) > 0:
        exp_rva, _exp_size = data_dirs[0]
        exp_off = _rva_to_offset(exp_rva, sections, len(data))
        if exp_off is not None and exp_off + 40 <= len(data):
            (
                _exp_chars,
                _exp_ts,
                _maj,
                _min,
                _exp_name_rva,
                ord_base,
                num_funcs,
                num_names,
                addr_funcs_rva,
                addr_names_rva,
                addr_ords_rva,
            ) = struct.unpack_from("<IIHHIIIIIII", data, exp_off)

            names_off = _rva_to_offset(addr_names_rva, sections, len(data))
            ords_off = _rva_to_offset(addr_ords_rva, sections, len(data))
            funcs_off = _rva_to_offset(addr_funcs_rva, sections, len(data))

            if names_off is not None and ords_off is not None and funcs_off is not None:
                limit = min(num_names, 4096)
                for i in range(limit):
                    if names_off + (i + 1) * 4 > len(data) or ords_off + (i + 1) * 2 > len(data):
                        break
                    fn_name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                    ord_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
                    fn_name_off = _rva_to_offset(fn_name_rva, sections, len(data))
                    fn_name = read_cstr(data, fn_name_off) if fn_name_off is not None else f"Ordinal#{ord_base + ord_idx}"

                    fn_rva = 0
                    if ord_idx < num_funcs and funcs_off + (ord_idx + 1) * 4 <= len(data):
                        fn_rva = struct.unpack_from("<I", data, funcs_off + ord_idx * 4)[0]

                    exports.append(
                        {
                            "name": fn_name,
                            "table": "ExportTable",
                            "bind": "EXPORT",
                            "type": "FUNC",
                            "value": image_base + fn_rva if fn_rva else 0,
                            "rva": fn_rva,
                            "ordinal": ord_base + ord_idx,
                            "size": 0,
                            "section": "EXPORT",
                            "imported": False,
                        }
                    )

    # Parse TLS Directory (Data Directory index 9) for pre-OEP TLS callbacks
    tls_callbacks: list[int] = []
    if len(data_dirs) > 9:
        tls_rva, _tls_size = data_dirs[9]
        tls_off = _rva_to_offset(tls_rva, sections, len(data))
        if tls_off is not None:
            cb_va = 0
            if bits == 64 and tls_off + 32 <= len(data):
                cb_va = struct.unpack_from("<Q", data, tls_off + 24)[0]
            elif bits == 32 and tls_off + 16 <= len(data):
                cb_va = struct.unpack_from("<I", data, tls_off + 12)[0]
            if cb_va > image_base:
                cb_off = _rva_to_offset(cb_va - image_base, sections, len(data))
                if cb_off is not None:
                    ptr_sz = 8 if bits == 64 else 4
                    ptr_fmt = "<Q" if bits == 64 else "<I"
                    pos = cb_off
                    while pos + ptr_sz <= len(data) and len(tls_callbacks) < 64:
                        fn_va = struct.unpack_from(ptr_fmt, data, pos)[0]
                        pos += ptr_sz
                        if fn_va == 0:
                            break
                        tls_callbacks.append(fn_va)

    is_dll = bool(characteristics & 0x2000)
    try:
        compile_time = datetime.datetime.fromtimestamp(
            timestamp, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        compile_time = f"0x{timestamp:08x}"

    mitigations: dict[str, str] = {
        "ASLR (DynamicBase)": "Enabled" if (dll_chars & 0x0040) else "Disabled",
        "High Entropy VA": "Enabled" if (dll_chars & 0x0020) else "Disabled",
        "DEP (NXCompat)": "Enabled" if (dll_chars & 0x0100) else "Disabled",
        "CFG (Control Flow Guard)": "Enabled" if (dll_chars & 0x4000) else "Disabled",
        "No SEH": "Yes" if (dll_chars & 0x0400) else "No",
    }

    return {
        "format": "PE",
        "header": {
            "class": pe_type,
            "bits": bits,
            "endianness": "Little Endian",
            "type": "DLL (Dynamic Link Library)" if is_dll else "EXE (Executable)",
            "architecture": PE_MACHINES.get(machine, f"Unknown (0x{machine:x})"),
            "subsystem": PE_SUBSYSTEMS.get(subsystem, f"Unknown ({subsystem})"),
            "image_base": image_base,
            "entry_point": image_base + entry_point_rva,
            "entry_point_rva": entry_point_rva,
            "timestamp": compile_time,
            "section_headers": len(sections),
        },
        "mitigations": mitigations,
        "tls_callbacks": tls_callbacks,
        "segments": [],
        "sections": sections,
        "needed_libraries": [imp["library"] for imp in imports],
        "imports": imports,
        "imported_symbols": imported_symbols,
        "symbols": exports,
        "exports": exports,
        "warnings": warnings,
    }
