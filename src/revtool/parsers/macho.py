"""Pure-Python Mach-O (32-bit, 64-bit, and Universal/Fat) static binary parser."""

from __future__ import annotations

import struct
from typing import Any

from revtool.utils import calculate_entropy, read_cstr


MACHO_CPUTYPES: dict[int, str] = {
    7: "x86 (i386)",
    0x01000007: "x86_64 (AMD64)",
    12: "ARM",
    0x0100000C: "AArch64 (ARM64)",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}

MACHO_FILETYPES: dict[int, str] = {
    1: "MH_OBJECT (Relocatable)",
    2: "MH_EXECUTE (Executable)",
    3: "MH_FVMLIB (Fixed VM Shared Lib)",
    4: "MH_CORE (Core File)",
    5: "MH_PRELOAD (Preloaded Executable)",
    6: "MH_DYLIB (Dynamic Library)",
    7: "MH_DYLINKER (Dynamic Linker)",
    8: "MH_BUNDLE (Plugin / Bundle)",
    10: "MH_DSYM (Debug Symbols)",
}


def _prot_to_perms(prot: int) -> str:
    r = "R" if (prot & 0x1) else "-"
    w = "W" if (prot & 0x2) else "-"
    x = "X" if (prot & 0x4) else "-"
    return f"{r}{w}{x}"


def _parse_single_macho(
    data: bytes,
    base_off: int,
    slice_size: int,
    fat_archs: list[str] | None = None,
) -> dict[str, Any]:
    warnings: list[str] = []
    if base_off + 28 > len(data) or slice_size < 28:
        return {"error": "Truncated Mach-O header."}

    magic_be = struct.unpack_from(">I", data, base_off)[0]
    if magic_be == 0xFEEDFACE:
        bits, endian_prefix, endian_name = 32, ">", "Big Endian"
    elif magic_be == 0xCEFAEDFE:
        bits, endian_prefix, endian_name = 32, "<", "Little Endian"
    elif magic_be == 0xFEEDFACF:
        bits, endian_prefix, endian_name = 64, ">", "Big Endian"
    elif magic_be == 0xCFFAEDFE:
        bits, endian_prefix, endian_name = 64, "<", "Little Endian"
    else:
        return {"error": f"Invalid Mach-O magic: 0x{magic_be:08x}"}

    hdr_size = 32 if bits == 64 else 28
    if base_off + hdr_size > len(data):
        return {"error": "Truncated Mach-O header."}

    if bits == 64:
        _magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _res = struct.unpack_from(
            f"{endian_prefix}IIIIIIII", data, base_off
        )
    else:
        _magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            f"{endian_prefix}IIIIIII", data, base_off
        )

    segments: list[dict[str, Any]] = []
    sections: list[dict[str, Any]] = []
    needed_libs: list[str] = []
    symbols: list[dict[str, Any]] = []
    imported_symbols: list[dict[str, Any]] = []
    init_functions: list[int] = []

    text_vmaddr = 0
    entry_offset: int | None = None
    has_code_sig = False
    is_encrypted = False
    has_canary = False
    has_local_syms = False
    symtab_info: tuple[int, int, int, int] | None = None

    pos = base_off + hdr_size
    cmds_end = min(len(data), base_off + hdr_size + sizeofcmds)
    sec_index = 0

    for idx in range(ncmds):
        if pos + 8 > cmds_end:
            warnings.append("Mach-O load commands truncated.")
            break
        cmd, cmdsize = struct.unpack_from(f"{endian_prefix}II", data, pos)
        if cmdsize < 8 or pos + cmdsize > len(data):
            warnings.append(f"Invalid Mach-O load command size at index {idx}.")
            break

        if cmd in (0x1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
            is_64_seg = cmd == 0x19
            min_seg_sz = 72 if is_64_seg else 56
            if cmdsize >= min_seg_sz:
                if is_64_seg:
                    raw_segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _sflags = (
                        struct.unpack_from(f"{endian_prefix}16sQQQQIIII", data, pos + 8)
                    )
                    sec_fmt = f"{endian_prefix}16s16sQQIIIIIIII"
                    sec_sz = 80
                else:
                    raw_segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _sflags = (
                        struct.unpack_from(f"{endian_prefix}16sIIIIIIII", data, pos + 8)
                    )
                    sec_fmt = f"{endian_prefix}16s16sIIIIIIIII"
                    sec_sz = 68

                segname = raw_segname.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                if segname == "__TEXT" and text_vmaddr == 0:
                    text_vmaddr = vmaddr

                seg_perms = _prot_to_perms(initprot)
                segments.append(
                    {
                        "index": len(segments),
                        "type": segname or "LC_SEGMENT",
                        "offset": base_off + fileoff,
                        "vaddr": vmaddr,
                        "filesz": filesize,
                        "memsz": vmsize,
                        "perms": seg_perms,
                        "align": 0x1000,
                    }
                )

                sec_pos = pos + min_seg_sz
                for _s in range(nsects):
                    if sec_pos + sec_sz > pos + cmdsize:
                        break
                    fields = struct.unpack_from(sec_fmt, data, sec_pos)
                    sec_pos += sec_sz
                    raw_sectname, raw_s_segname, s_addr, s_size, s_off, _align, _reloff, _nreloc, s_flags = fields[:9]
                    sectname = raw_sectname.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    s_segname = raw_s_segname.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    abs_off = base_off + s_off
                    sec_entropy = 0.0
                    # S_ZEROFILL = 0x1
                    if (s_flags & 0xFF) != 0x1 and s_size > 0 and abs_off < len(data):
                        sec_bytes = data[abs_off : min(len(data), abs_off + s_size)]
                        sec_entropy = calculate_entropy(sec_bytes)

                    # S_MOD_INIT_FUNC_POINTERS = 0x9
                    if (s_flags & 0xFF) == 0x9 and s_size > 0 and abs_off + s_size <= len(data):
                        psz = 8 if is_64_seg else 4
                        pfmt = f"{endian_prefix}Q" if is_64_seg else f"{endian_prefix}I"
                        ppos = abs_off
                        while ppos + psz <= abs_off + s_size:
                            ptr = struct.unpack_from(pfmt, data, ppos)[0]
                            if ptr:
                                init_functions.append(ptr)
                            ppos += psz

                    sections.append(
                        {
                            "index": sec_index,
                            "name": f"{s_segname},{sectname}" if s_segname else sectname,
                            "type": f"0x{s_flags & 0xFF:x}",
                            "addr": s_addr,
                            "offset": abs_off,
                            "size": s_size,
                            "perms": seg_perms,
                            "entropy": sec_entropy,
                        }
                    )
                    sec_index += 1

        elif cmd in (0xC, 0x80000018, 0x8000001F, 0x80000020):  # LC_LOAD_DYLIB & variants
            if cmdsize >= 24:
                name_off = struct.unpack_from(f"{endian_prefix}I", data, pos + 8)[0]
                if 8 <= name_off < cmdsize:
                    dylib_name = read_cstr(data, pos + name_off)
                    if dylib_name:
                        needed_libs.append(dylib_name)

        elif cmd == 0x2:  # LC_SYMTAB
            if cmdsize >= 24:
                symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian_prefix}IIII", data, pos + 8)
                symtab_info = (base_off + symoff, nsyms, base_off + stroff, strsize)

        elif cmd == 0x80000028:  # LC_MAIN
            if cmdsize >= 16:
                entry_offset = struct.unpack_from(f"{endian_prefix}Q", data, pos + 8)[0]

        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            has_code_sig = True

        elif cmd in (0x21, 0x2C):  # LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
            if cmdsize >= 20:
                _cryptoff, _cryptsize, cryptid = struct.unpack_from(f"{endian_prefix}III", data, pos + 12 if cmd == 0x21 else pos + 8)
                # For both 32/64bit, cryptid is at offset 16 (pos + 16)
                cryptid = struct.unpack_from(f"{endian_prefix}I", data, pos + 16)[0]
                if cryptid != 0:
                    is_encrypted = True

        pos += cmdsize

    # Parse nlist / nlist_64 symbols
    if symtab_info is not None:
        symoff, nsyms, stroff, strsize = symtab_info
        ent_sz = 16 if bits == 64 else 12
        nlist_fmt = f"{endian_prefix}IBBHQ" if bits == 64 else f"{endian_prefix}IBBHI"
        for i in range(min(nsyms, 20000)):
            off = symoff + i * ent_sz
            if off + ent_sz > len(data):
                break
            n_strx, n_type, n_sect, _n_desc, n_value = struct.unpack_from(nlist_fmt, data, off)
            if n_type & 0xE0:  # skip N_STAB debug entries
                continue
            name = read_cstr(data, stroff + n_strx) if 0 < n_strx < strsize else ""
            if not name:
                continue
            if "stack_chk_fail" in name or "stack_chk_guard" in name:
                has_canary = True
            n_type_masked = n_type & 0x0E
            is_ext = bool(n_type & 0x01)
            is_und = n_type_masked == 0x00 and is_ext
            if not is_und and n_type_masked == 0x0E:  # N_SECT defined symbol
                has_local_syms = True
            sec_name = (
                "UND" if is_und else (
                    sections[n_sect - 1]["name"] if 1 <= n_sect <= len(sections) else str(n_sect)
                )
            )
            entry = {
                "name": name,
                "table": "Symtab",
                "bind": "EXTERNAL" if is_ext else "LOCAL",
                "type": "FUNC" if (not is_und and "X" in (sections[n_sect - 1]["perms"] if 1 <= n_sect <= len(sections) else "")) else "SYM",
                "value": n_value,
                "size": 0,
                "section": sec_name,
                "imported": is_und,
            }
            symbols.append(entry)
            if is_und:
                imported_symbols.append(entry)

    entry_point = (text_vmaddr + entry_offset) if (entry_offset is not None and text_vmaddr) else (entry_offset or 0)
    is_pie = bool(flags & 0x200000)
    allow_stack_exec = bool(flags & 0x20000)

    mitigations: dict[str, str] = {
        "PIE": "Enabled (MH_PIE)" if is_pie else "Disabled",
        "NX (Stack)": "Disabled (Allow Stack Exec)" if allow_stack_exec else "Enabled",
        "Stack Canary": "Found" if has_canary else "Not Found",
        "Code Signature": "Present" if has_code_sig else "Not Found",
        "Encrypted (FairPlay)": "Yes (cryptid != 0)" if is_encrypted else "No",
        "Stripped": "No (symbols present)" if has_local_syms else "Yes (minimal/stripped)",
    }

    header: dict[str, Any] = {
        "class": f"Mach-O {bits}-bit",
        "bits": bits,
        "endianness": endian_name,
        "type": MACHO_FILETYPES.get(filetype, f"0x{filetype:x}"),
        "architecture": MACHO_CPUTYPES.get(cputype, f"Unknown (0x{cputype:x})"),
        "entry_point": entry_point,
        "load_commands": ncmds,
        "section_headers": len(sections),
        "program_headers": len(segments),
    }
    if fat_archs:
        header["fat_architectures"] = fat_archs

    return {
        "format": "MACH-O",
        "header": header,
        "mitigations": mitigations,
        "init_functions": init_functions,
        "segments": segments,
        "sections": sections,
        "needed_libraries": needed_libs,
        "imports": [{"library": lib, "functions": []} for lib in needed_libs],
        "imported_symbols": imported_symbols,
        "symbols": symbols,
        "exports": [s for s in symbols if not s["imported"] and s["bind"] == "EXTERNAL"],
        "warnings": warnings,
    }


def parse_macho(data: bytes) -> dict[str, Any]:
    """Parse Mach-O 32/64-bit or Universal/Fat Mach-O binaries."""
    if len(data) < 28:
        return {"error": "File too small to be a Mach-O binary."}

    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be == 0xCAFEBABE:
        if len(data) < 8:
            return {"error": "Truncated Mach-O Fat header."}
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat == 0 or nfat > 32:
            return {"error": "Not a valid Mach-O Fat binary (possibly Java .class)."}
        archs: list[tuple[int, int, int]] = []
        fat_names: list[str] = []
        for i in range(nfat):
            off = 8 + i * 20
            if off + 20 > len(data):
                break
            cputype, _sub, slice_off, slice_size, _align = struct.unpack_from(">IIIII", data, off)
            fat_names.append(MACHO_CPUTYPES.get(cputype, f"0x{cputype:x}"))
            if slice_off + slice_size <= len(data):
                archs.append((cputype, slice_off, slice_size))
        if not archs:
            return {"error": "Mach-O Fat binary contains no valid architecture slices."}
        # Prefer x86_64 or arm64 slice first
        archs.sort(key=lambda a: (0 if a[0] == 0x01000007 else (1 if a[0] == 0x0100000C else 2)))
        _cpu, chosen_off, chosen_sz = archs[0]
        return _parse_single_macho(data, chosen_off, chosen_sz, fat_archs=fat_names)

    return _parse_single_macho(data, 0, len(data))
