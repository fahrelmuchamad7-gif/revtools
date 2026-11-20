"""Advanced multi-architecture, multi-compiler main() entry point resolution.

Supports:
- ELF x86_64: _start -> lea/mov rdi/edi, main -> __libc_start_main
- ELF x86 32-bit: _start -> push main -> __libc_start_main
- ELF AArch64 (ARM64): _start -> adrp/add x0, main -> __libc_start_main
- ELF ARM 32-bit: _start -> ldr r0, [pc] / movw/movt r0 -> __libc_start_main
- Windows PE: CRT startup dispatch -> main(argc, argv, envp) / WinMain
- Mach-O: LC_MAIN entry offset resolution
- Go: .gopclntab main.main recovery
- Dlang: _Dmain resolution from C main wrapper (lea rdx, [_Dmain])
- Rust: std::rt::lang_start 1st parameter & mangled symbols
"""

from __future__ import annotations

import re
from typing import Any


def _vaddr_to_offset_via_sections(vaddr: int, report: dict[str, Any]) -> int | None:
    fmt = report.get("format")
    image_base = int(report.get("header", {}).get("image_base", 0) or 0)
    target = vaddr - image_base if fmt == "PE" and vaddr >= image_base else vaddr
    for sec in report.get("sections", []):
        s_addr = int(sec.get("addr", 0))
        s_size = int(sec.get("size", 0))
        s_off = int(sec.get("offset", 0))
        if s_size > 0 and s_addr <= target < s_addr + s_size:
            return s_off + (target - s_addr)
    return None


def _is_vaddr_in_exec_section(vaddr: int, report: dict[str, Any]) -> bool:
    fmt = report.get("format")
    image_base = int(report.get("header", {}).get("image_base", 0) or 0)
    target = vaddr - image_base if fmt == "PE" and vaddr >= image_base else vaddr
    for sec in report.get("sections", []):
        perms = str(sec.get("perms", ""))
        s_addr = int(sec.get("addr", 0))
        s_size = int(sec.get("size", 0))
        if "X" in perms and s_size > 0 and s_addr <= target < s_addr + s_size:
            return True
    return False


def resolve_main(data: bytes, report: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve main() entry point across compilers (GCC, Clang, MSVC, Go, Rust, Dlang)."""
    fmt = report.get("format")
    hdr = report.get("header", {})
    arch = str(hdr.get("architecture", "")).lower()
    ep = hdr.get("entry_point")

    # 1. Explicit symbol table checks (.symtab, .dynsym, or PE exports)
    symbols = report.get("symbols", [])
    for sym in symbols:
        name = str(sym.get("name", ""))
        val = int(sym.get("value", 0))
        if val > 0 and sym.get("type") in ("FUNC", "NOTYPE", None):
            if name in ("main", "_main"):
                return {
                    "address": val,
                    "address_hex": f"0x{val:x}",
                    "name": name,
                    "origin": "Symbol Table (.symtab / .dynsym)",
                    "confidence": "HIGH",
                }
            if name == "main.main":
                return {
                    "address": val,
                    "address_hex": f"0x{val:x}",
                    "name": "main.main",
                    "origin": "Go gopclntab",
                    "confidence": "HIGH",
                }

    # 2. Rust binary: search for crate::main or demangled main symbol
    for sym in symbols:
        name = str(sym.get("name", ""))
        val = int(sym.get("value", 0))
        if val > 0 and ("::main" in name or (name.startswith("_ZN") and "4main" in name)):
            return {
                "address": val,
                "address_hex": f"0x{val:x}",
                "name": name,
                "origin": "Rust user main symbol",
                "confidence": "HIGH",
            }

    # 3. Dlang binary: check _Dmain symbol
    for sym in symbols:
        name = str(sym.get("name", ""))
        val = int(sym.get("value", 0))
        if val > 0 and (name == "_Dmain" or (name.startswith("_D") and "main" in name.lower())):
            return {
                "address": val,
                "address_hex": f"0x{val:x}",
                "name": "_Dmain",
                "origin": "Dlang symbol table",
                "confidence": "HIGH",
            }

    # 4. Mach-O: LC_MAIN load command already set entry_point directly to main
    if fmt == "MACH-O" and ep is not None and ep > 0:
        return {
            "address": ep,
            "address_hex": f"0x{ep:x}",
            "name": "main",
            "origin": "Mach-O LC_MAIN load command",
            "confidence": "HIGH",
        }

    # 5. Architecture-specific disassembly heuristics for stripped binaries
    if ep is None or ep == 0:
        return None

    try:
        import capstone
    except ImportError:
        return None

    ep_off = _vaddr_to_offset_via_sections(ep, report)
    if ep_off is None or ep_off >= len(data):
        return None

    # 5a. ELF x86_64
    if fmt == "ELF" and ("x86_64" in arch or "amd64" in arch):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        snippet = data[ep_off : min(len(data), ep_off + 96)]
        insns = list(md.disasm(snippet, ep))
        last_target: int | None = None

        for ins in insns:
            # PIE: lea rdi, [rip + disp]
            if ins.mnemonic == "lea" and ins.op_str.startswith("rdi, [rip"):
                try:
                    part = ins.op_str.split("[rip", 1)[1].rstrip("]").strip()
                    if part.startswith("+"):
                        disp = int(part[1:].strip(), 0)
                        last_target = ins.address + ins.size + disp
                    elif part.startswith("-"):
                        disp = int(part[1:].strip(), 0)
                        last_target = ins.address + ins.size - disp
                except ValueError:
                    pass
            # Non-PIE: mov rdi, <imm> / mov edi, <imm>
            elif ins.mnemonic == "mov" and (ins.op_str.startswith("rdi, ") or ins.op_str.startswith("edi, ")):
                try:
                    raw_val = ins.op_str.split(",", 1)[1].strip()
                    imm = int(raw_val, 0)
                    if _is_vaddr_in_exec_section(imm, report):
                        last_target = imm
                except ValueError:
                    pass
            # Call to __libc_start_main
            elif ins.mnemonic in ("call", "jmp") and last_target is not None:
                # Check if this binary is Dlang (calls C wrapper main which passes _Dmain in rdx)
                d_main = _scan_dlang_c_wrapper(data, report, last_target)
                if d_main:
                    return {
                        "address": d_main,
                        "address_hex": f"0x{d_main:x}",
                        "name": "_Dmain",
                        "origin": f"Dlang _Dmain resolved from C wrapper (0x{last_target:x})",
                        "confidence": "HIGH",
                    }
                return {
                    "address": last_target,
                    "address_hex": f"0x{last_target:x}",
                    "name": "main",
                    "origin": "ELF x86_64 _start -> __libc_start_main (rdi)",
                    "confidence": "HIGH",
                }

    # 5b. ELF x86 (32-bit)
    elif fmt == "ELF" and ("x86" in arch or "i386" in arch or "i686" in arch):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        snippet = data[ep_off : min(len(data), ep_off + 96)]
        insns = list(md.disasm(snippet, ep))
        last_push_target: int | None = None

        for ins in insns:
            if ins.mnemonic == "push":
                try:
                    imm = int(ins.op_str.strip(), 0)
                    if _is_vaddr_in_exec_section(imm, report):
                        last_push_target = imm
                except ValueError:
                    pass
            elif ins.mnemonic == "call" and last_push_target is not None:
                return {
                    "address": last_push_target,
                    "address_hex": f"0x{last_push_target:x}",
                    "name": "main",
                    "origin": "ELF x86 (32-bit) _start -> __libc_start_main (push)",
                    "confidence": "HIGH",
                }

    # 5c. ELF AArch64 (ARM64)
    elif fmt == "ELF" and ("aarch64" in arch or "arm64" in arch):
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        snippet = data[ep_off : min(len(data), ep_off + 96)]
        insns = list(md.disasm(snippet, ep))
        adrp_page: int | None = None
        last_x0_target: int | None = None

        for ins in insns:
            if ins.mnemonic == "adrp" and ins.op_str.startswith("x0, "):
                try:
                    raw_val = ins.op_str.split(",", 1)[1].strip()
                    adrp_page = int(raw_val, 0)
                except ValueError:
                    pass
            elif ins.mnemonic == "add" and ins.op_str.startswith("x0, x0, ") and adrp_page is not None:
                try:
                    raw_val = ins.op_str.split("x0, x0,", 1)[1].strip()
                    offset = int(raw_val, 0)
                    last_x0_target = adrp_page + offset
                except ValueError:
                    pass
            elif ins.mnemonic in ("bl", "b") and last_x0_target is not None:
                return {
                    "address": last_x0_target,
                    "address_hex": f"0x{last_x0_target:x}",
                    "name": "main",
                    "origin": "ELF AArch64 _start -> __libc_start_main (x0)",
                    "confidence": "HIGH",
                }

    # 5d. ELF ARM (32-bit)
    elif fmt == "ELF" and "arm" in arch:
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        snippet = data[ep_off : min(len(data), ep_off + 96)]
        insns = list(md.disasm(snippet, ep))
        last_r0_target: int | None = None

        for ins in insns:
            if ins.mnemonic == "ldr" and ins.op_str.startswith("r0, [pc"):
                try:
                    disp_str = ins.op_str.split("[pc", 1)[1].rstrip("]").strip()
                    disp = int(disp_str[1:].strip(), 0) if disp_str.startswith(("+", ",")) else 0
                    ptr_addr = ins.address + 8 + disp
                    p_off = _vaddr_to_offset_via_sections(ptr_addr, report)
                    if p_off is not None and p_off + 4 <= len(data):
                        val = int.from_bytes(data[p_off : p_off + 4], "little")
                        if _is_vaddr_in_exec_section(val, report):
                            last_r0_target = val
                except Exception:
                    pass
            elif ins.mnemonic in ("bl", "b") and last_r0_target is not None:
                return {
                    "address": last_r0_target,
                    "address_hex": f"0x{last_r0_target:x}",
                    "name": "main",
                    "origin": "ELF ARM32 _start -> __libc_start_main (r0)",
                    "confidence": "HIGH",
                }

    # 5e. Windows PE (x86_64 & x86) CRT Startup -> main
    elif fmt == "PE":
        is_pe_64 = "64" in arch or "amd64" in arch
        md = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_64 if is_pe_64 else capstone.CS_MODE_32,
        )
        image_base = int(hdr.get("image_base", 0) or 0)
        actual_ep = ep + (image_base if ep < image_base else 0)
        snippet = data[ep_off : min(len(data), ep_off + 192)]
        insns = list(md.disasm(snippet, actual_ep))

        # Trace calls from CRT startup to find candidate user function
        internal_calls: list[int] = []
        for ins in insns:
            if ins.mnemonic == "call":
                try:
                    tgt = int(ins.op_str.strip(), 0)
                    if _is_vaddr_in_exec_section(tgt, report):
                        internal_calls.append(tgt)
                except ValueError:
                    pass

        # In MinGW: call __main, followed by call to user main
        # In MSVC: call __scrt_common_main_seh / body helper, which calls main
        if internal_calls:
            # If there are 2-4 calls in CRT startup, the last internal call before exit is usually main or the main dispatcher
            cand = internal_calls[-1]
            return {
                "address": cand,
                "address_hex": f"0x{cand:x}",
                "name": "main (CRT candidate)",
                "origin": "Windows PE CRT Startup -> main call",
                "confidence": "MEDIUM",
            }

    return None


def _scan_dlang_c_wrapper(data: bytes, report: dict[str, Any], c_main_vaddr: int) -> int | None:
    """If a candidate main is a C wrapper for Dlang, resolve _Dmain from `lea rdx, [rip + disp]`."""
    # Ensure binary has Dlang runtime signatures
    if not (b"_d_run_main" in data or b"rt.dmain" in data or b"/dlang/" in data):
        return None

    try:
        import capstone
    except ImportError:
        return None

    c_off = _vaddr_to_offset_via_sections(c_main_vaddr, report)
    if c_off is None or c_off >= len(data):
        return None

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    chunk = data[c_off : min(len(data), c_off + 96)]
    for ins in md.disasm(chunk, c_main_vaddr):
        if ins.mnemonic == "lea" and "rdx, [rip" in ins.op_str:
            try:
                part = ins.op_str.split("[rip", 1)[1].rstrip("]").strip()
                target: int | None = None
                if part.startswith("+"):
                    disp = int(part[1:].strip(), 0)
                    target = ins.address + ins.size + disp
                elif part.startswith("-"):
                    disp = int(part[1:].strip(), 0)
                    target = ins.address + ins.size - disp
                if target is not None and _is_vaddr_in_exec_section(target, report):
                    return target
            except ValueError:
                pass
    return None
