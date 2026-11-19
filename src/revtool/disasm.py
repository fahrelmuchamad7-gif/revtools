"""Static disassembly helper powered by Capstone (capstone-engine/capstone)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from revtool.parsers import analyze_file


def _resolve_capstone_arch(report: dict[str, Any]):
    """Map parsed ELF/PE header architecture to (cs_arch, cs_mode)."""
    import capstone

    hdr = report.get("header", {})
    arch = str(hdr.get("architecture", "")).lower()
    bits = int(hdr.get("bits", 64) or 64)
    endian = str(hdr.get("endianness", "Little Endian")).lower()
    is_big = "big" in endian
    end_flag = capstone.CS_MODE_BIG_ENDIAN if is_big else capstone.CS_MODE_LITTLE_ENDIAN

    if "x86_64" in arch or "amd64" in arch:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    if "x86" in arch or "i386" in arch:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32
    if "aarch64" in arch or "arm64" in arch:
        return capstone.CS_ARCH_ARM64, end_flag
    if "arm" in arch:
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | end_flag
    if "mips" in arch:
        mode = capstone.CS_MODE_MIPS64 if bits == 64 else capstone.CS_MODE_MIPS32
        return capstone.CS_ARCH_MIPS, mode | end_flag
    if "riscv" in arch or "risc-v" in arch:
        mode = capstone.CS_MODE_RISCV64 if bits == 64 else capstone.CS_MODE_RISCV32
        return capstone.CS_ARCH_RISCV, mode

    raise ValueError(f"Unsupported architecture for disassembly: {hdr.get('architecture', 'Unknown')}")


def _vaddr_to_file_offset(vaddr: int, report: dict[str, Any]) -> int | None:
    """Convert a virtual address to raw file offset using sections or ELF segments."""
    fmt = report.get("format")
    image_base = int(report.get("header", {}).get("image_base", 0) or 0)
    target_rva = vaddr - image_base if fmt == "PE" and vaddr >= image_base else vaddr

    for sec in report.get("sections", []):
        sec_addr = int(sec.get("addr", 0))
        sec_size = int(sec.get("size", 0))
        sec_off = int(sec.get("offset", 0))
        if sec_size > 0 and sec_addr <= target_rva < sec_addr + sec_size:
            return sec_off + (target_rva - sec_addr)

    for seg in report.get("segments", []):
        seg_vaddr = int(seg.get("vaddr", 0))
        seg_filesz = int(seg.get("filesz", 0))
        seg_off = int(seg.get("offset", 0))
        if seg_filesz > 0 and seg_vaddr <= vaddr < seg_vaddr + seg_filesz:
            return seg_off + (vaddr - seg_vaddr)

    return None


def disassemble_file(
    file_path: str | Path,
    section_name: str | None = None,
    address: int | None = None,
    count: int = 30,
) -> dict[str, Any]:
    """Disassemble instructions from entry point, named section, or virtual address."""
    try:
        import capstone
    except ImportError as exc:
        raise RuntimeError(
            "Capstone is not installed. Run `pip install capstone` to enable disassembly."
        ) from exc

    path = Path(file_path)
    report = analyze_file(path)
    fmt = report.get("format")
    if fmt not in ("ELF", "PE", "MACH-O"):
        raise ValueError(f"Disassembly supports ELF/PE/Mach-O binaries (detected format: {fmt}).")

    cs_arch, cs_mode = _resolve_capstone_arch(report)
    data = path.read_bytes()

    target_vaddr: int
    file_offset: int | None
    max_bytes = max(count * 16, 256)

    if section_name:
        matched = [s for s in report.get("sections", []) if s.get("name") == section_name]
        if not matched:
            raise ValueError(f"Section '{section_name}' not found.")
        sec = matched[0]
        file_offset = int(sec["offset"])
        image_base = int(report.get("header", {}).get("image_base", 0) or 0)
        target_vaddr = int(sec["addr"]) + (image_base if fmt == "PE" else 0)
        max_bytes = min(int(sec["size"]), max_bytes)
    else:
        if address is not None:
            target_vaddr = address
        else:
            ep = report.get("header", {}).get("entry_point")
            if ep is None:
                raise ValueError("Could not determine binary entry point.")
            target_vaddr = int(ep)
        file_offset = _vaddr_to_file_offset(target_vaddr, report)

    if file_offset is None or file_offset < 0 or file_offset >= len(data):
        raise ValueError(f"Could not map address 0x{target_vaddr:x} to a valid file offset.")

    code = data[file_offset : min(len(data), file_offset + max_bytes)]
    md = capstone.Cs(cs_arch, cs_mode)

    instructions: list[dict[str, str]] = []
    for insn in md.disasm(code, target_vaddr):
        instructions.append(
            {
                "address": f"0x{insn.address:x}",
                "bytes": insn.bytes.hex(" "),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            }
        )
        if len(instructions) >= count:
            break

    return {
        "file": str(path),
        "format": fmt,
        "architecture": report["header"].get("architecture", "Unknown"),
        "start_address": f"0x{target_vaddr:x}",
        "file_offset": f"0x{file_offset:x}",
        "instructions": instructions,
    }
