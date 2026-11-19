"""Pure-Python ELF32 and ELF64 static binary parser."""

from __future__ import annotations

import struct
from typing import Any

from revtool.utils import calculate_entropy, read_cstr


ELF_TYPES: dict[int, str] = {
    0: "ET_NONE (None)",
    1: "ET_REL (Relocatable)",
    2: "ET_EXEC (Executable)",
    3: "ET_DYN (Shared Object / PIE)",
    4: "ET_CORE (Core File)",
}

ELF_MACHINES: dict[int, str] = {
    0: "None",
    2: "SPARC",
    3: "x86 (i386)",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    42: "SuperH",
    43: "SPARCv9",
    50: "IA-64",
    62: "x86_64 (AMD64)",
    183: "AArch64 (ARM64)",
    243: "RISC-V",
    247: "eBPF",
    258: "LoongArch",
}

ELF_OSABI: dict[int, str] = {
    0: "UNIX - System V",
    1: "HP-UX",
    2: "NetBSD",
    3: "UNIX - GNU/Linux",
    6: "Solaris",
    7: "AIX",
    8: "IRIX",
    9: "FreeBSD",
    12: "OpenBSD",
}

PT_TYPES: dict[int, str] = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
    0x6474E553: "PT_GNU_PROPERTY",
}

SHT_TYPES: dict[int, str] = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFD: "VERDEF",
    0x6FFFFFFE: "VERNEED",
    0x6FFFFFFF: "VERSYM",
}

STT_TYPES: dict[int, str] = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    10: "GNU_IFUNC",
}

STB_BINDS: dict[int, str] = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
    10: "GNU_UNIQUE",
}


def _elf_section_perms(flags: int) -> str:
    r = "R" if (flags & 0x2) else "-"  # SHF_ALLOC implies readable in memory
    w = "W" if (flags & 0x1) else "-"  # SHF_WRITE
    x = "X" if (flags & 0x4) else "-"  # SHF_EXECINSTR
    return f"{r}{w}{x}"


def _elf_segment_perms(flags: int) -> str:
    r = "R" if (flags & 0x4) else "-"
    w = "W" if (flags & 0x2) else "-"
    x = "X" if (flags & 0x1) else "-"
    return f"{r}{w}{x}"


def parse_elf(data: bytes) -> dict[str, Any]:
    """Parse ELF32/ELF64 headers, segments, sections, dynamic tags, and symbols."""
    warnings: list[str] = []
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {"error": "Not a valid ELF binary (too small or missing ELF magic)."}

    ei_class = data[4]
    ei_data = data[5]
    ei_osabi = data[7]

    if ei_class == 1:
        bits = 32
        elf_class = "ELF32"
    elif ei_class == 2:
        bits = 64
        elf_class = "ELF64"
    else:
        return {"error": f"Unknown ELF class: {ei_class}"}

    if ei_data == 1:
        endian_prefix = "<"
        endian_name = "Little Endian"
    elif ei_data == 2:
        endian_prefix = ">"
        endian_name = "Big Endian"
    else:
        return {"error": f"Unknown ELF endianness: {ei_data}"}

    if bits == 64:
        if len(data) < 64:
            return {"error": "Truncated ELF64 header."}
        header_fmt = f"{endian_prefix}HHIQQQIHHHHHH"
        (
            e_type,
            e_machine,
            _e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            _e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from(header_fmt, data, 16)
    else:
        header_fmt = f"{endian_prefix}HHIIIIIHHHHHH"
        (
            e_type,
            e_machine,
            _e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            _e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from(header_fmt, data, 16)

    # Parse Program Headers (Segments)
    segments: list[dict[str, Any]] = []
    interpreter: str | None = None
    has_gnu_stack = False
    gnu_stack_exec = False
    has_gnu_relro = False

    if e_phoff > 0 and e_phnum > 0 and e_phentsize > 0:
        expected_phent = 56 if bits == 64 else 32
        if e_phentsize < expected_phent:
            warnings.append(f"Unexpected program header entry size: {e_phentsize}")
        else:
            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                if off + expected_phent > len(data):
                    warnings.append("Program header table truncated.")
                    break
                if bits == 64:
                    p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = (
                        struct.unpack_from(f"{endian_prefix}IIQQQQQQ", data, off)
                    )
                else:
                    p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, p_align = (
                        struct.unpack_from(f"{endian_prefix}IIIIIIII", data, off)
                    )

                type_name = PT_TYPES.get(p_type, f"0x{p_type:x}")
                segments.append(
                    {
                        "index": i,
                        "type": type_name,
                        "offset": p_offset,
                        "vaddr": p_vaddr,
                        "filesz": p_filesz,
                        "memsz": p_memsz,
                        "perms": _elf_segment_perms(p_flags),
                        "align": p_align,
                    }
                )

                if p_type == 3 and p_filesz > 0 and p_offset < len(data):  # PT_INTERP
                    interp_bytes = data[p_offset : min(len(data), p_offset + p_filesz)]
                    interpreter = interp_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                elif p_type == 0x6474E551:  # PT_GNU_STACK
                    has_gnu_stack = True
                    gnu_stack_exec = bool(p_flags & 0x1)
                elif p_type == 0x6474E552:  # PT_GNU_RELRO
                    has_gnu_relro = True

    # Parse Section Headers
    raw_sections: list[dict[str, Any]] = []
    if e_shoff > 0 and e_shnum > 0 and e_shentsize > 0:
        expected_shent = 64 if bits == 64 else 40
        if e_shentsize < expected_shent:
            warnings.append(f"Unexpected section header entry size: {e_shentsize}")
        else:
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                if off + expected_shent > len(data):
                    warnings.append("Section header table truncated.")
                    break
                if bits == 64:
                    (
                        sh_name,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack_from(f"{endian_prefix}IIQQQQIIQQ", data, off)
                else:
                    (
                        sh_name,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack_from(f"{endian_prefix}IIIIIIIIII", data, off)

                raw_sections.append(
                    {
                        "index": i,
                        "sh_name": sh_name,
                        "sh_type": sh_type,
                        "sh_flags": sh_flags,
                        "addr": sh_addr,
                        "offset": sh_offset,
                        "size": sh_size,
                        "sh_link": sh_link,
                        "sh_info": sh_info,
                        "align": sh_addralign,
                        "entsize": sh_entsize,
                    }
                )

    # Resolve section names via shstrtab
    shstr_offset = None
    shstr_size = 0
    if 0 <= e_shstrndx < len(raw_sections):
        shstr_offset = raw_sections[e_shstrndx]["offset"]
        shstr_size = raw_sections[e_shstrndx]["size"]

    sections: list[dict[str, Any]] = []
    has_symtab = False
    for sec in raw_sections:
        name = ""
        if shstr_offset is not None and sec["sh_name"] < shstr_size:
            name = read_cstr(data, shstr_offset + sec["sh_name"])
        if sec["sh_type"] == 2:  # SHT_SYMTAB
            has_symtab = True

        # Calculate entropy for non-NOBITS sections that fit in file
        sec_entropy = 0.0
        if sec["sh_type"] != 8 and sec["size"] > 0 and sec["offset"] < len(data):
            sec_bytes = data[sec["offset"] : min(len(data), sec["offset"] + sec["size"])]
            sec_entropy = calculate_entropy(sec_bytes)

        sections.append(
            {
                "index": sec["index"],
                "name": name,
                "type": SHT_TYPES.get(sec["sh_type"], f"0x{sec['sh_type']:x}"),
                "addr": sec["addr"],
                "offset": sec["offset"],
                "size": sec["size"],
                "perms": _elf_section_perms(sec["sh_flags"]),
                "entropy": sec_entropy,
                "_raw": sec,
            }
        )

    # Parse Dynamic section (DT_NEEDED, RPATH/RUNPATH, BIND_NOW, PIE flag)
    needed_libs: list[str] = []
    rpaths: list[str] = []
    runpaths: list[str] = []
    bind_now = False
    df_1_pie = False

    for sec in raw_sections:
        if sec["sh_type"] != 6:  # SHT_DYNAMIC
            continue
        link_idx = sec["sh_link"]
        dynstr_off = None
        dynstr_size = 0
        if 0 <= link_idx < len(raw_sections):
            dynstr_off = raw_sections[link_idx]["offset"]
            dynstr_size = raw_sections[link_idx]["size"]

        ent_size = sec["entsize"] or (16 if bits == 64 else 8)
        dyn_fmt = f"{endian_prefix}qQ" if bits == 64 else f"{endian_prefix}iI"
        start = sec["offset"]
        end = min(len(data), start + sec["size"])
        pos = start
        while pos + ent_size <= end:
            d_tag, d_val = struct.unpack_from(dyn_fmt, data, pos)
            pos += ent_size
            if d_tag == 0:  # DT_NULL
                break
            elif d_tag == 1 and dynstr_off is not None and d_val < dynstr_size:  # DT_NEEDED
                needed_libs.append(read_cstr(data, dynstr_off + d_val))
            elif d_tag == 15 and dynstr_off is not None and d_val < dynstr_size:  # DT_RPATH
                rpaths.append(read_cstr(data, dynstr_off + d_val))
            elif d_tag == 29 and dynstr_off is not None and d_val < dynstr_size:  # DT_RUNPATH
                runpaths.append(read_cstr(data, dynstr_off + d_val))
            elif d_tag == 24:  # DT_BIND_NOW
                bind_now = True
            elif d_tag == 30 and (d_val & 0x8):  # DT_FLAGS & DF_BIND_NOW
                bind_now = True
            elif d_tag == 0x6FFFFFFB:  # DT_FLAGS_1
                if d_val & 0x1:  # DF_1_NOW
                    bind_now = True
                if d_val & 0x08000000:  # DF_1_PIE
                    df_1_pie = True

    # Parse Symbols (.dynsym and .symtab) + preserve dynsym ordered names for PLT resolution
    symbols: list[dict[str, Any]] = []
    imported_symbols: list[dict[str, Any]] = []
    dynsym_names: dict[int, str] = {}
    has_canary = False

    for sec in raw_sections:
        if sec["sh_type"] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
            continue
        table_name = ".symtab" if sec["sh_type"] == 2 else ".dynsym"
        link_idx = sec["sh_link"]
        if not (0 <= link_idx < len(raw_sections)):
            continue
        strtab_off = raw_sections[link_idx]["offset"]
        strtab_size = raw_sections[link_idx]["size"]

        ent_size = sec["entsize"] or (24 if bits == 64 else 16)
        min_size = 24 if bits == 64 else 16
        if ent_size < min_size:
            continue

        start = sec["offset"]
        end = min(len(data), start + sec["size"])
        pos = start
        sym_idx = 0
        while pos + min_size <= end:
            if bits == 64:
                st_name, st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    f"{endian_prefix}IBBHQQ", data, pos
                )
            else:
                st_name, st_value, st_size, st_info, _st_other, st_shndx = struct.unpack_from(
                    f"{endian_prefix}IIIBBH", data, pos
                )
            pos += ent_size
            cur_idx = sym_idx
            sym_idx += 1

            sym_name = ""
            if st_name > 0 and st_name < strtab_size:
                sym_name = read_cstr(data, strtab_off + st_name)
            if table_name == ".dynsym" and sym_name:
                dynsym_names[cur_idx] = sym_name
            if not sym_name:
                continue

            if sym_name in ("__stack_chk_fail", "__stack_chk_guard"):
                has_canary = True

            st_bind = STB_BINDS.get(st_info >> 4, str(st_info >> 4))
            st_type = STT_TYPES.get(st_info & 0xF, str(st_info & 0xF))
            sec_label = "UND" if st_shndx == 0 else (
                "ABS" if st_shndx == 0xFFF1 else (
                    sections[st_shndx]["name"] if 0 <= st_shndx < len(sections) else str(st_shndx)
                )
            )

            entry = {
                "name": sym_name,
                "table": table_name,
                "bind": st_bind,
                "type": st_type,
                "value": st_value,
                "size": st_size,
                "section": sec_label,
                "imported": st_shndx == 0,
            }
            symbols.append(entry)

            if table_name == ".dynsym" and st_shndx == 0:
                imported_symbols.append(entry)

    # Clean internal _raw helper key from sections
    clean_sections = [
        {k: v for k, v in s.items() if k != "_raw"}
        for s in sections
    ]

    # Build standard binary hardening/compilation metadata summary
    if e_type == 3:
        pie_status = "Enabled (PIE)" if (df_1_pie or interpreter) else "Shared Object / PIE (ET_DYN)"
    elif e_type == 2:
        pie_status = "Disabled (ET_EXEC)"
    else:
        pie_status = ELF_TYPES.get(e_type, f"Type {e_type}")

    if has_gnu_stack:
        nx_status = "Disabled (Executable Stack)" if gnu_stack_exec else "Enabled"
    else:
        nx_status = "Default / No PT_GNU_STACK"

    if has_gnu_relro:
        relro_status = "Full RELRO" if bind_now else "Partial RELRO"
    else:
        relro_status = "No RELRO"

    metadata_flags: dict[str, str] = {
        "PIE": pie_status,
        "NX": nx_status,
        "RELRO": relro_status,
        "Stack Canary": "Found" if has_canary else "Not Found",
        "Stripped": "No (.symtab present)" if has_symtab else "Yes (no .symtab)",
    }
    if rpaths:
        metadata_flags["RPATH"] = ":".join(rpaths)
    if runpaths:
        metadata_flags["RUNPATH"] = ":".join(runpaths)

    # Parse .init_array function pointers (pre-main constructors)
    init_functions: list[int] = []
    ptr_fmt = f"{endian_prefix}Q" if bits == 64 else f"{endian_prefix}I"
    ptr_sz = 8 if bits == 64 else 4
    for sec in raw_sections:
        if sec["sh_type"] == 14 and sec["size"] > 0:  # SHT_INIT_ARRAY
            s_off = sec["offset"]
            s_end = min(len(data), s_off + sec["size"])
            pos = s_off
            while pos + ptr_sz <= s_end:
                ptr = struct.unpack_from(ptr_fmt, data, pos)[0]
                if ptr != 0 and ptr != ((1 << (ptr_sz * 8)) - 1):
                    init_functions.append(ptr)
                pos += ptr_sz

    # Build GOT -> symbol map from .rela.plt / .rela.dyn / .rel.plt, then match x86_64 PLT stubs
    got_to_sym: dict[int, str] = {}
    for sec in raw_sections:
        if sec["sh_type"] not in (4, 9):  # SHT_RELA=4, SHT_REL=9
            continue
        is_rela = sec["sh_type"] == 4
        ent_sz = sec["entsize"] or ((24 if is_rela else 16) if bits == 64 else (12 if is_rela else 8))
        pos = sec["offset"]
        end = min(len(data), pos + sec["size"])
        while pos + ent_sz <= end:
            if bits == 64:
                r_offset, r_info = struct.unpack_from(f"{endian_prefix}QQ", data, pos)
                sym_idx = r_info >> 32
            else:
                r_offset, r_info = struct.unpack_from(f"{endian_prefix}II", data, pos)
                sym_idx = r_info >> 8
            pos += ent_sz
            if sym_idx in dynsym_names and r_offset != 0:
                got_to_sym[r_offset] = dynsym_names[sym_idx]

    plt_map: dict[int, str] = {}
    if e_machine == 62 and got_to_sym:  # x86_64 RIP-relative jmp [rip + disp32] (ff 25 disp32)
        for sec in clean_sections:
            if sec["name"] in (".plt", ".plt.sec", ".plt.got"):
                s_off = sec["offset"]
                s_addr = sec["addr"]
                s_size = sec["size"]
                if s_off + s_size > len(data) or s_size < 6:
                    continue
                chunk = data[s_off : s_off + s_size]
                i = 0
                while i + 6 <= len(chunk):
                    if chunk[i] == 0xFF and chunk[i + 1] == 0x25:
                        disp = struct.unpack_from("<i", chunk, i + 2)[0]
                        stub_start = s_addr + i
                        # Check standard 16-byte stub header (endbr64 = f3 0f 1e fa before ff 25)
                        if i >= 4 and chunk[i - 4 : i] == b"\xf3\x0f\x1e\xfa":
                            stub_start -= 4
                        got_addr = (s_addr + i + 6) + disp
                        if got_addr in got_to_sym:
                            plt_map[stub_start] = got_to_sym[got_addr]
                            plt_map[s_addr + i] = got_to_sym[got_addr]
                    i += 1

    # Group imports cleanly for unified display
    imports_grouped: list[dict[str, Any]] = [
        {
            "library": lib,
            "functions": [],
        }
        for lib in needed_libs
    ]

    return {
        "format": "ELF",
        "header": {
            "class": elf_class,
            "bits": bits,
            "endianness": endian_name,
            "type": ELF_TYPES.get(e_type, f"0x{e_type:x}"),
            "architecture": ELF_MACHINES.get(e_machine, f"Unknown (0x{e_machine:x})"),
            "os_abi": ELF_OSABI.get(ei_osabi, f"0x{ei_osabi:x}"),
            "entry_point": e_entry,
            "flags": e_flags,
            "interpreter": interpreter,
            "program_headers": len(segments),
            "section_headers": len(clean_sections),
        },
        "mitigations": metadata_flags,
        "init_functions": init_functions,
        "plt_map": plt_map,
        "segments": segments,
        "sections": clean_sections,
        "needed_libraries": needed_libs,
        "imports": imports_grouped,
        "imported_symbols": imported_symbols,
        "symbols": symbols,
        "exports": [
            s for s in symbols
            if s["table"] == ".dynsym" and not s["imported"] and s["bind"] in ("GLOBAL", "WEAK")
        ],
        "warnings": warnings,
    }
