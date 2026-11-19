"""Deep static reconnaissance engine for national-level CTF reverse engineering."""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import Any

from revtool.crypto_scan import (
    map_offset_to_section,
    scan_crypto_constants,
    scan_embedded_magic,
)
from revtool.parsers import analyze_file
from revtool.strings_scan import extract_strings
from revtool.utils import calculate_entropy, read_cstr


API_CATEGORIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "Dynamic Code / RWX Memory": (
        "HIGH",
        (
            "mmap", "mmap64", "mprotect", "pkey_mprotect", "memfd_create",
            "dlopen", "dlsym", "dlmopen",
            "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
            "ntallocatevirtualmemory", "ntprotectvirtualmemory",
            "loadlibrary", "getprocaddress", "rtladdfunctiontable",
        ),
    ),
    "Signal / Exception Obfuscation": (
        "HIGH",
        (
            "signal", "sigaction", "rt_sigaction", "sigaltstack", "sigprocmask",
            "setunhandledexceptionfilter", "addvectoredexceptionhandler",
            "removevectoredexceptionhandler", "raiseexception",
        ),
    ),
    "Anti-Debug / Anti-Analysis / Timing": (
        "HIGH",
        (
            "ptrace", "prctl", "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "ntsetinformationthread",
            "outputdebugstring", "clock_gettime", "gettimeofday",
            "queryperformancecounter", "gettickcount",
        ),
    ),
    "Crypto / Hashing / PRNG": (
        "MEDIUM",
        (
            "evp_", "aes_", "sha256", "sha1", "md5", "cryptacquirecontext",
            "cryptdecrypt", "cryptencrypt", "bcrypt", "ncrypt",
            "srand", "rand", "random", "srandom", "arc4random", "getrandom",
        ),
    ),
    "Process / Execution / Network": (
        "INFO",
        (
            "execve", "execvp", "execl", "system", "popen", "fork", "vfork",
            "clone", "createprocess", "shellexecute", "winexec",
            "socket", "connect", "bind", "listen", "accept", "wsastartup",
            "internetopen", "urldownloadtofile",
        ),
    ),
}

ANDROID_PACKER_SIGNATURES: list[tuple[str, str]] = [
    ("libdpt", "DPT-Shell Android DEX Protector"),
    ("dpt-shell", "DPT-Shell Android DEX Protector"),
    ("libjiagu", "Qihoo 360 Jiagu Packer"),
    ("libdexhelper", "Bangcle / SecNeo Packer"),
    ("libsecexe", "Bangcle Packer"),
    ("libtup", "Tencent Legu Packer"),
    ("libshell", "Tencent / Generic Shell Packer"),
    ("libexec", "Baidu / Ijiami Packer"),
    ("libpairip", "Google Play Pairip Protection"),
    ("libil2cpp.so", "Unity IL2CPP Native Binary"),
    ("libflutter.so", "Flutter AOT Dart Binary (libapp.so holds Dart code)"),
    ("libapp.so", "Flutter Dart AOT Snapshot"),
    ("libreactnativejni.so", "React Native / Hermes JS Bundle"),
]


def fingerprint_runtime(
    data: bytes,
    report: dict[str, Any],
) -> list[str]:
    """Identify compiler, language, runtime, or packer fingerprints."""
    if report.get("format") not in ("ELF", "PE", "MACH-O", "WASM", "DEX"):
        return []

    tags: list[str] = []
    sec_names = {str(s.get("name", "")).lower() for s in report.get("sections", [])}
    sym_names = " ".join(str(s.get("name", "")) for s in report.get("symbols", []))
    libs = " ".join(str(l) for l in report.get("needed_libraries", [])).lower()

    if ".gopclntab" in sec_names or b"Go build ID:" in data or b"runtime.main" in data:
        go_ver = re.search(rb"go1\.\d+(?:\.\d+)?", data)
        if go_ver:
            tags.append(f"Go (Golang) Binary ({go_ver.group().decode('ascii', errors='ignore')})")
        else:
            tags.append("Go (Golang) Binary")
    if ".rustc" in sec_names or b"rust_eh_personality" in data or b"core::panicking" in data:
        tags.append("Rust Binary")
    if b"__zig_" in data or b"std.os." in data or b"zig-cache" in data:
        tags.append("Zig Binary")
    if b"NimMain" in data or b"nimZeroMem" in data:
        tags.append("Nim Binary")
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in data or b"PYZ-\x00" in data:
        py_ver = re.search(rb"python3\d+|libpython3\.\d+", data, re.I)
        if py_ver:
            tags.append(f"PyInstaller Bundle ({py_ver.group().decode('ascii', errors='ignore')})")
        else:
            tags.append("PyInstaller Bundle (Python)")
    if b"BSJB" in data and ("mscoree.dll" in libs or b"_CorExeMain" in data):
        tags.append(".NET / CLR Assembly")
    if b"UPX!" in data or "upx0" in sec_names or "upx1" in sec_names:
        tags.append("UPX Packed")
    elif report.get("format") in ("ELF", "PE") and report.get("file", {}).get("entropy", 0.0) >= 7.1:
        imp_cnt = len(report.get("imported_symbols", []))
        if imp_cnt <= 8 and any("W" in str(s.get("perms", "")) and "X" in str(s.get("perms", "")) for s in report.get("sections", [])):
            tags.append("Custom / Patched Packer Suspect (High entropy + WX + minimal imports)")
    if "__cxa_throw" in sym_names or "libstdc++" in libs or b"_ZTV" in data:
        tags.append("C++ (RTTI / libstdc++ signatures)")

    if report.get("format") == "WASM":
        tags.append("WebAssembly Module (.wasm)")
    if not tags and report.get("format") in ("ELF", "PE"):
        tags.append("Native C / C++ / Assembly Binary")

    return tags


def _normalize_sym(name: str) -> str:
    """Strip common ELF/PE symbol prefixes/version suffixes for matching."""
    base = name.split("@", 1)[0].split("@@", 1)[0]
    for prefix in ("__imp_", "_imp_", "__isoc99_", "__isoc23_"):
        if base.startswith(prefix):
            base = base[len(prefix) :]
    return base.lstrip("_").lower()


_GO_RUNTIME_BOILERPLATE = {
    "virtualalloc", "virtualfree", "virtualprotect",
    "addvectoredexceptionhandler", "removevectoredexceptionhandler",
    "setunhandledexceptionfilter", "raiseexception",
    "loadlibrary", "getprocaddress",
    "mmap", "sigaction", "rt_sigaction", "sigaltstack", "sigprocmask",
    "clock_gettime", "gettimeofday", "queryperformancecounter", "gettickcount",
}


def classify_api_behaviors(
    report: dict[str, Any],
    is_go: bool = False,
) -> list[dict[str, Any]]:
    """Group imported/exported/dynamic symbols into RE behavioral categories."""
    candidates: list[str] = []
    seen: set[str] = set()
    for sym in report.get("imported_symbols", []) + report.get("symbols", []):
        name = str(sym.get("name", ""))
        if name and name not in seen:
            seen.add(name)
            candidates.append(name)

    findings: list[dict[str, Any]] = []
    for category, (severity, patterns) in API_CATEGORIES.items():
        matched: list[str] = []
        non_go_matched: list[str] = []
        for sym_name in candidates:
            norm = _normalize_sym(sym_name)
            if not norm or sym_name.startswith("_ITM_"):
                continue
            for pat in patterns:
                if pat.endswith("_"):
                    hit = norm.startswith(pat)
                else:
                    hit = norm == pat or norm.startswith(pat + "64") or norm.startswith(pat + "ex")
                if hit:
                    matched.append(sym_name)
                    if not (is_go and any(norm == b or norm.startswith(b + "ex") or norm.startswith(b + "a") or norm.startswith(b + "w") for b in _GO_RUNTIME_BOILERPLATE)):
                        non_go_matched.append(sym_name)
                    break
        if matched:
            eff_sev = "GO_RUNTIME" if (is_go and not non_go_matched) else severity
            findings.append(
                {
                    "category": category,
                    "severity": eff_sev,
                    "symbols": sorted(matched),
                }
            )
    return findings


def find_entropy_blobs(
    data: bytes,
    sections: list[dict[str, Any]] | None = None,
    image_base: int = 0,
    fmt: str = "ELF",
    window: int = 128,
    stride: int = 64,
    threshold: float = 6.8,
    min_blob_size: int = 128,
    exclude_ranges: list[tuple[int, int]] | None = None,
) -> list[dict[str, Any]]:
    """Locate contiguous high-entropy byte regions using a sliding window."""
    sections = sections or []
    exclude_ranges = exclude_ranges or []
    n = len(data)
    if n < window:
        return []

    regions: list[tuple[int, int, list[float]]] = []
    cur_start: int | None = None
    cur_end = 0
    cur_ents: list[float] = []

    for off in range(0, n - window + 1, stride):
        ent = calculate_entropy(data[off : off + window])
        if ent >= threshold:
            if cur_start is None:
                cur_start = off
                cur_end = off + window
                cur_ents = [ent]
            elif off <= cur_end:
                cur_end = off + window
                cur_ents.append(ent)
            else:
                regions.append((cur_start, cur_end, cur_ents))
                cur_start = off
                cur_end = off + window
                cur_ents = [ent]
        else:
            if cur_start is not None:
                regions.append((cur_start, cur_end, cur_ents))
                cur_start = None
                cur_ents = []

    if cur_start is not None:
        regions.append((cur_start, cur_end, cur_ents))

    blobs: list[dict[str, Any]] = []
    for start, end, _ents in regions:
        size = end - start
        if size < min_blob_size:
            continue
        # Skip blobs that mostly overlap already-identified crypto lookup tables
        if exclude_ranges:
            overlapped = sum(
                max(0, min(end, ex_end) - max(start, ex_start))
                for ex_start, ex_end in exclude_ranges
            )
            if overlapped >= size * 0.5:
                continue
        exact_ent = calculate_entropy(data[start:end])
        sec_name, vaddr = map_offset_to_section(start, sections, image_base, fmt)
        blobs.append(
            {
                "offset": start,
                "end": end,
                "size": size,
                "vaddr": vaddr,
                "section": sec_name,
                "entropy": exact_ent,
                "preview_hex": data[start : min(end, start + 16)].hex(" "),
            }
        )

    blobs.sort(key=lambda b: (-b["entropy"], -b["size"]))
    return blobs


def scan_code_anomalies(
    data: bytes,
    report: dict[str, Any],
    max_scan_bytes: int = 262144,
    is_go: bool = False,
) -> dict[str, Any]:
    """Scan executable sections via Capstone for trap/anti-debug instructions & stripped main()."""
    result: dict[str, Any] = {
        "anomalies": [],
        "main_candidate": None,
    }
    fmt = report.get("format")
    if fmt not in ("ELF", "PE", "MACH-O"):
        return result

    hdr = report.get("header", {})
    arch = str(hdr.get("architecture", "")).lower()
    if "x86_64" not in arch and "amd64" not in arch and "x86" not in arch:
        return result

    try:
        import capstone
    except ImportError:
        return result

    is_64 = "x86_64" in arch or "amd64" in arch
    md = capstone.Cs(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32,
    )
    image_base = int(hdr.get("image_base", 0) or 0)

    # Heuristic for stripped ELF x86_64 _start -> main:
    # Look near entry point for `lea rdi, [rip + disp]` followed soon by `call`
    ep = hdr.get("entry_point")
    if fmt == "ELF" and is_64 and ep is not None:
        for sec in report.get("sections", []):
            s_addr = int(sec.get("addr", 0))
            s_size = int(sec.get("size", 0))
            s_off = int(sec.get("offset", 0))
            if s_size > 0 and s_addr <= ep < s_addr + s_size:
                ep_off = s_off + (ep - s_addr)
                snippet = data[ep_off : min(len(data), ep_off + 96)]
                insns = list(md.disasm(snippet, ep))
                last_lea_target: int | None = None
                for ins in insns:
                    if ins.mnemonic == "lea" and ins.op_str.startswith("rdi, [rip"):
                        # Compute rip-relative target from displacement
                        # ins.address + ins.size + disp
                        try:
                            part = ins.op_str.split("[rip", 1)[1].rstrip("]").strip()
                            if part.startswith("+"):
                                disp = int(part[1:].strip(), 0)
                                last_lea_target = ins.address + ins.size + disp
                            elif part.startswith("-"):
                                disp = int(part[1:].strip(), 0)
                                last_lea_target = ins.address + ins.size - disp
                        except ValueError:
                            pass
                    elif ins.mnemonic == "call" and last_lea_target is not None:
                        result["main_candidate"] = f"0x{last_lea_target:x}"
                        break

    # Scan executable sections (focus on .text first, or any X section)
    interesting_mnemonics: dict[str, str] = {
        "hlt": "Privileged halt instruction (often signal-based control flow or anti-debug)",
        "ud2": "Undefined instruction trap (SIGILL obfuscation / anti-analysis)",
        "int3": "Software breakpoint trap (SIGTRAP / anti-debugger)",
        "rdtsc": "CPU timestamp counter (timing anti-debug check)",
        "rdtscp": "Serializing CPU timestamp counter (timing anti-debug check)",
        "cpuid": "CPU identification (anti-VM / environment check)",
        "syscall": "Direct raw syscall (bypasses libc PLT/GOT hooks)",
        "sysenter": "Direct 32-bit raw syscall",
    }

    anomalies: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    indirect_jumps: list[str] = []
    scanned = 0

    for sec in report.get("sections", []):
        sec_name = str(sec.get("name", ""))
        perms = str(sec.get("perms", ""))
        if "X" not in perms:
            continue
        if sec_name in (".plt", ".plt.got", ".plt.sec", ".init", ".fini"):
            continue
        s_off = int(sec.get("offset", 0))
        s_size = int(sec.get("size", 0))
        s_addr = int(sec.get("addr", 0)) + (image_base if fmt == "PE" else 0)
        if s_size <= 0 or s_off >= len(data):
            continue

        take = min(s_size, max(0, max_scan_bytes - scanned))
        if take <= 0:
            break
        scanned += take
        chunk = data[s_off : min(len(data), s_off + take)]

        insns = list(md.disasm(chunk, s_addr))
        for i, ins in enumerate(insns):
            mn = ins.mnemonic.lower()
            desc = interesting_mnemonics.get(mn)
            if mn == "int" and ins.op_str.strip() in ("3", "0x3", "0x2d", "0x80"):
                desc = f"Software interrupt `int {ins.op_str}` (trap / anti-debug / raw syscall)"

            # Filter Go runtime cpuid probe and int3 (0xcc) alignment padding
            if is_go and mn == "cpuid":
                desc = None
            if mn == "int3":
                # Count consecutive int3 instructions around index i
                run_len = 1
                j = i - 1
                while j >= 0 and insns[j].mnemonic.lower() == "int3":
                    run_len += 1
                    j -= 1
                k = i + 1
                while k < len(insns) and insns[k].mnemonic.lower() == "int3":
                    run_len += 1
                    k += 1
                prev_mn = insns[j].mnemonic.lower() if j >= 0 else ""
                if is_go and (run_len >= 2 or prev_mn in ("ret", "jmp", "nop", "ud2")):
                    desc = None
                elif not is_go and run_len >= 4 and prev_mn in ("ret", "jmp", "nop", "ud2"):
                    desc = None

            if desc:
                counts[mn] = counts.get(mn, 0) + 1
                if counts[mn] <= 5:
                    anomalies.append(
                        {
                            "mnemonic": mn,
                            "op_str": ins.op_str,
                            "address": f"0x{ins.address:x}",
                            "section": sec_name or "<unnamed>",
                            "reason": desc,
                        }
                    )
            elif not is_go and mn == "jmp" and ("[" in ins.op_str and "rip" not in ins.op_str or ins.op_str in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "eax", "ebx", "ecx", "edx")):
                # Skip standard GCC CRT tm_clones tail jumps right after _start
                in_crt_window = ep is not None and (ep + 0x28) <= ins.address <= (ep + 0xC0)
                if not in_crt_window and len(indirect_jumps) < 10:
                    indirect_jumps.append(f"0x{ins.address:x} ({ins.mnemonic} {ins.op_str})")

    result["anomalies"] = anomalies
    result["anomaly_counts"] = counts
    result["indirect_jumps"] = indirect_jumps
    return result


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


def analyze_main_flow(
    data: bytes,
    report: dict[str, Any],
    main_candidate: str | None,
) -> dict[str, Any] | None:
    """Trace main() statically via Capstone to summarize calls, strings, and inline magic."""
    fmt = report.get("format")
    if fmt not in ("ELF", "PE", "MACH-O"):
        return None
    hdr = report.get("header", {})
    arch = str(hdr.get("architecture", "")).lower()
    if "x86_64" not in arch and "amd64" not in arch:
        return None

    try:
        import capstone
    except ImportError:
        return None

    main_addr: int | None = None
    for sym in report.get("symbols", []):
        if sym.get("name") in ("main", "_main", "main.main") and int(sym.get("value", 0)) > 0:
            main_addr = int(sym["value"])
            break
    if main_addr is None and main_candidate:
        try:
            main_addr = int(main_candidate, 16)
        except ValueError:
            main_addr = None
    if main_addr is None:
        return None

    main_off = _vaddr_to_offset_via_sections(main_addr, report)
    if main_off is None or main_off >= len(data):
        return None

    plt_map: dict[int, str] = report.get("plt_map", {})
    sym_addr_map: dict[int, str] = {
        int(s["value"]): str(s["name"])
        for s in report.get("symbols", [])
        if int(s.get("value", 0)) > 0 and s.get("name")
    }

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    chunk = data[main_off : min(len(data), main_off + 512)]

    calls: list[str] = []
    data_refs: list[str] = []
    inline_hints: list[str] = []
    seen_calls: set[str] = set()
    seen_refs: set[str] = set()
    seen_hints: set[str] = set()

    inline_constants: dict[int, str] = {
        0x811C9DC5: "FNV-1a 32-bit offset basis (0x811c9dc5)",
        0x01000193: "FNV-1a 32-bit prime (0x1000193)",
        0x9E3779B9: "TEA / XTEA delta (0x9e3779b9)",
        0x61707865: "ChaCha20/Salsa20 constant ('expa')",
        0xEDB88320: "CRC32 polynomial (0xedb88320)",
    }

    max_branch_target = main_addr
    for idx, ins in enumerate(md.disasm(chunk, main_addr)):
        if idx >= 120:
            break
        mn = ins.mnemonic.lower()
        op = ins.op_str.strip()

        # Track internal forward branch targets so we don't stop early on a mid-function ret
        if mn.startswith("j") and op.startswith("0x"):
            try:
                btgt = int(op, 16)
                if main_addr <= btgt < main_addr + 512:
                    max_branch_target = max(max_branch_target, btgt)
            except ValueError:
                pass

        # Check argc comparison near function prologue
        if idx < 15 and mn == "cmp" and op.startswith("edi, "):
            val = op.split(",", 1)[1].strip()
            h = f"Checks argc == {val}"
            if h not in seen_hints:
                seen_hints.add(h)
                inline_hints.append(h)

        # Check known inline magic constants
        for const_val, label in inline_constants.items():
            if f"0x{const_val:x}" in op.lower() and label not in seen_hints:
                seen_hints.add(label)
                inline_hints.append(label)

        # Resolve call or tail-jmp targets
        if mn in ("call", "jmp") and op.startswith("0x"):
            try:
                tgt = int(op, 16)
            except ValueError:
                tgt = None
            if tgt is not None:
                if mn == "jmp" and main_addr <= tgt < main_addr + 512:
                    pass  # internal branch inside main
                else:
                    label = plt_map.get(tgt) or sym_addr_map.get(tgt)
                    if label:
                        entry = f"{label.split('@', 1)[0]}@plt (0x{tgt:x})" if tgt in plt_map else f"{label} (0x{tgt:x})"
                    else:
                        entry = f"sub_0x{tgt:x}"
                    if mn == "jmp":
                        entry = f"tail-jmp -> {entry}"
                    if entry not in seen_calls:
                        seen_calls.add(entry)
                        calls.append(entry)
                    if mn == "jmp" and ins.address >= max_branch_target:
                        break

        # Resolve RIP-relative data/string references (`lea r.., [rip +/- disp]`)
        if mn == "lea" and "[rip" in op:
            try:
                part = op.split("[rip", 1)[1].rstrip("]").strip()
                tgt = None
                if part.startswith("+"):
                    tgt = ins.address + ins.size + int(part[1:].strip(), 0)
                elif part.startswith("-"):
                    tgt = ins.address + ins.size - int(part[1:].strip(), 0)
                if tgt is not None:
                    d_off = _vaddr_to_offset_via_sections(tgt, report)
                    if d_off is not None and d_off < len(data):
                        s_preview = read_cstr(data, d_off, max_len=64)
                        printable = sum(1 for c in s_preview if 32 <= ord(c) <= 126)
                        if len(s_preview) >= 3 and printable == len(s_preview):
                            ref_str = f"0x{tgt:x} -> \"{s_preview}\""
                        else:
                            ref_str = f"0x{tgt:x}"
                        if ref_str not in seen_refs and len(data_refs) < 10:
                            seen_refs.add(ref_str)
                            data_refs.append(ref_str)
            except ValueError:
                pass

        if mn == "ret" and ins.address >= max_branch_target:
            break

    return {
        "address": f"0x{main_addr:x}",
        "calls": calls[:15],
        "data_refs": data_refs[:10],
        "inline_hints": inline_hints,
    }


def annotate_go_blob_xrefs(
    data: bytes,
    report: dict[str, Any],
    blobs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Tag Go high-entropy blobs with whether any `main.*` user function references them."""
    if not blobs:
        return blobs

    main_funcs = [
        s for s in report.get("symbols", [])
        if s.get("table") == ".gopclntab"
        and str(s.get("name", "")).startswith("main.")
        and int(s.get("value", 0)) > 0
    ]
    if not main_funcs:
        return blobs

    hdr = report.get("header", {})
    arch = str(hdr.get("architecture", "")).lower()
    if "x86_64" not in arch and "amd64" not in arch and "x86" not in arch:
        return blobs

    try:
        import capstone
    except ImportError:
        return blobs

    is_64 = "x86_64" in arch or "amd64" in arch
    md = capstone.Cs(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32,
    )

    # Collect (target_vaddr, fn_name) references emitted by `main.*` functions
    refs: list[tuple[int, str]] = []
    for fn in main_funcs[:60]:
        fn_vaddr = int(fn["value"])
        fn_name = str(fn["name"])
        fn_size = int(fn.get("size", 0) or 0)
        fn_off = _vaddr_to_offset_via_sections(fn_vaddr, report)
        if fn_off is None or fn_off >= len(data):
            continue
        take = min(fn_size if fn_size > 0 else 2048, 8192)
        chunk = data[fn_off : min(len(data), fn_off + take)]
        for ins in md.disasm(chunk, fn_vaddr):
            mn = ins.mnemonic.lower()
            op = ins.op_str.strip()
            if mn in ("lea", "mov") and "[rip" in op:
                try:
                    part = op.split("[rip", 1)[1].split("]", 1)[0].strip()
                    if part.startswith("+"):
                        refs.append((ins.address + ins.size + int(part[1:].strip(), 0), fn_name))
                    elif part.startswith("-"):
                        refs.append((ins.address + ins.size - int(part[1:].strip(), 0), fn_name))
                except ValueError:
                    pass
            elif mn in ("mov", "push") and "0x" in op:
                # Capture direct immediate VA references (e.g. non-PIE or 32-bit `mov reg, 0x...`)
                tail = op.rsplit(",", 1)[-1].strip()
                if tail.startswith("0x"):
                    try:
                        imm = int(tail, 16)
                        if imm >= 0x10000:
                            refs.append((imm, fn_name))
                    except ValueError:
                        pass

    for blob in blobs:
        b_vaddr = blob.get("vaddr")
        b_size = int(blob.get("size", 0))
        matched_funcs: list[str] = []
        if b_vaddr is not None and refs:
            lo = int(b_vaddr) - 64
            hi = int(b_vaddr) + b_size
            seen_fn: set[str] = set()
            for r_vaddr, r_name in refs:
                if lo <= r_vaddr < hi and r_name not in seen_fn:
                    seen_fn.add(r_name)
                    matched_funcs.append(r_name)
        blob["xref_main"] = matched_funcs
        if matched_funcs:
            preview = ", ".join(matched_funcs[:2])
            if len(matched_funcs) > 2:
                preview += f" (+{len(matched_funcs) - 2})"
            blob["xref_label"] = f"main.* ({preview})"
        else:
            blob["xref_label"] = "Go stdlib/runtime (no main.* xref)"

    # Surface user-referenced blobs before stdlib/runtime tables
    blobs.sort(key=lambda b: (0 if b.get("xref_main") else 1, -b["entropy"], -b["size"]))
    return blobs


def inspect_wasm(data: bytes) -> dict[str, Any] | None:
    """Parse basic WebAssembly (.wasm) sections and exported names."""
    if len(data) < 8 or not data.startswith(b"\x00asm"):
        return None
    wasm_sec_names = {
        0: "Custom", 1: "Type", 2: "Import", 3: "Function", 4: "Table",
        5: "Memory", 6: "Global", 7: "Export", 8: "Start", 9: "Element",
        10: "Code", 11: "Data", 12: "DataCount",
    }

    def _read_uleb(pos: int) -> tuple[int, int]:
        res = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            res |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return res, pos

    sections: list[str] = []
    exports: list[str] = []
    pos = 8
    while pos < len(data):
        sec_id = data[pos]
        pos += 1
        sec_len, pos = _read_uleb(pos)
        sec_end = min(len(data), pos + sec_len)
        sections.append(wasm_sec_names.get(sec_id, f"Sec#{sec_id}"))
        if sec_id == 7:  # Export section
            try:
                cnt, ep = _read_uleb(pos)
                for _ in range(min(cnt, 64)):
                    nlen, ep = _read_uleb(ep)
                    if ep + nlen + 1 > sec_end:
                        break
                    name = data[ep : ep + nlen].decode("utf-8", errors="replace")
                    ep += nlen
                    _kind = data[ep]
                    ep += 1
                    _idx, ep = _read_uleb(ep)
                    exports.append(name)
            except Exception:
                pass
        pos = sec_end
    return {"sections": sections, "exports": exports[:25]}


def _scan_zip_bytes(data: bytes, depth: int = 0) -> dict[str, Any] | None:
    """Inspect ZIP / Android APK archives (including 1-level nested .apk/.zip)."""
    if not data.startswith(b"PK\x03\x04"):
        return None

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None

    infos = zf.infolist()
    names = [info.filename for info in infos]
    is_apk = "AndroidManifest.xml" in names or any(n.endswith(".dex") for n in names)

    dex_files = [n for n in names if n.endswith(".dex")]
    native_libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    nested_executables = [
        n for n in names if n.endswith((".apk", ".zip", ".jar", ".so", ".elf", ".exe", ".dll"))
    ]

    packer_hints: list[str] = []
    seen_packers: set[str] = set()
    for name in names:
        lower = name.lower()
        for sig, label in ANDROID_PACKER_SIGNATURES:
            if sig in lower and label not in seen_packers:
                seen_packers.add(label)
                packer_hints.append(f"{label} (matched '{name}')")

    # Peek 1 level deep into nested .apk / .zip if this outer zip isn't already an APK
    nested_apk_info: dict[str, Any] | None = None
    if not is_apk and depth == 0:
        for info in infos:
            if info.filename.lower().endswith(".apk") and 0 < info.file_size <= 64 * 1024 * 1024:
                try:
                    nested_apk_info = _scan_zip_bytes(zf.read(info.filename), depth=1)
                    if nested_apk_info:
                        nested_apk_info["source_entry"] = info.filename
                        break
                except Exception:
                    pass

    high_entropy_entries: list[dict[str, Any]] = []
    for info in infos[:300]:
        if info.is_dir() or info.file_size == 0 or info.file_size > 20 * 1024 * 1024:
            continue
        if info.filename.endswith((".png", ".jpg", ".jpeg", ".webp", ".ogg", ".mp3")):
            continue
        if info.filename.endswith((".dex", ".so", ".bin", ".dat", ".apk")):
            try:
                content = zf.read(info.filename)
            except Exception:
                continue
            ent = calculate_entropy(content[:65536])
            high_entropy_entries.append(
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "entropy": ent,
                }
            )

    high_entropy_entries.sort(key=lambda x: (-x["entropy"], -x["size"]))

    # Extra deep APK recon: Manifest hints, DEX interesting strings/crypto, and packer/native ELF check
    manifest_components: list[str] = []
    dex_strings: list[dict[str, Any]] = []
    dex_crypto: list[dict[str, Any]] = []
    native_elf_checks: list[dict[str, Any]] = []

    if is_apk:
        if "AndroidManifest.xml" in names:
            try:
                manifest_bytes = zf.read("AndroidManifest.xml")
                raw_strs = extract_strings(manifest_bytes, min_len=4, encoding="both")
                seen_comp: set[str] = set()
                for s in raw_strs:
                    val = s["value"].strip()
                    if any(tok in val for tok in ("Activity", "Provider", "Service", "Receiver", "://")) or (
                        "." in val and not val.startswith(("android.", "http://schemas.")) and len(val) >= 8 and " " not in val
                    ):
                        if val not in seen_comp:
                            seen_comp.add(val)
                            manifest_components.append(val)
                    if len(manifest_components) >= 20:
                        break
            except Exception:
                pass

        for dex_name in dex_files[:3]:
            try:
                dex_bytes = zf.read(dex_name)
                if len(dex_bytes) <= 12 * 1024 * 1024:
                    for item in extract_strings(dex_bytes, min_len=5, encoding="ascii", only_interesting=True)[:25]:
                        item["section"] = dex_name
                        dex_strings.append(item)
                    for c in scan_crypto_constants(dex_bytes)[:10]:
                        c["section"] = dex_name
                        dex_crypto.append(c)
            except Exception:
                pass

        # Inspect up to 2 representative .so libraries (prefer x86_64/arm64 packer or native lib)
        from revtool.parsers.elf import parse_elf

        so_candidates = [n for n in nested_executables if n.endswith(".so")]
        preferred_so = sorted(
            so_candidates,
            key=lambda p: (
                0 if "libdpt" in p.lower() or "jiagu" in p.lower() or "dexhelper" in p.lower() else 1,
                0 if ("arm64" in p or "x86_64" in p) else 1,
                p,
            ),
        )
        seen_so_names: set[str] = set()
        for so_path in preferred_so:
            base_so = so_path.rsplit("/", 1)[-1]
            if base_so in seen_so_names:
                continue
            try:
                so_bytes = zf.read(so_path)
                if len(so_bytes) <= 15 * 1024 * 1024 and so_bytes.startswith(b"\x7fELF"):
                    parsed_so = parse_elf(so_bytes)
                    if "error" not in parsed_so:
                        seen_so_names.add(base_so)
                        native_elf_checks.append(
                            {
                                "entry": so_path,
                                "arch": parsed_so["header"].get("architecture", "-"),
                                "stripped": parsed_so["mitigations"].get("Stripped", "-"),
                                "behaviors": classify_api_behaviors(parsed_so),
                            }
                        )
            except Exception:
                pass
            if len(native_elf_checks) >= 2:
                break

    return {
        "kind": "Android APK" if is_apk else "ZIP Archive",
        "total_entries": len(infos),
        "has_manifest": "AndroidManifest.xml" in names,
        "dex_files": dex_files,
        "native_libs": native_libs[:30],
        "nested_executables": nested_executables[:30],
        "packer_hints": packer_hints,
        "notable_entries": high_entropy_entries[:15],
        "manifest_components": manifest_components,
        "dex_strings": dex_strings[:20],
        "dex_crypto": dex_crypto[:10],
        "native_elf_checks": native_elf_checks,
        "nested_apk": nested_apk_info,
    }


def inspect_archive(data: bytes) -> dict[str, Any] | None:
    """Inspect ZIP / Android APK archives for RE artifacts & mobile packers."""
    return _scan_zip_bytes(data, depth=0)


def run_recon(file_path: str | Path) -> dict[str, Any]:
    """Run deep static CTF reverse engineering reconnaissance on a file."""
    path = Path(file_path)
    report = analyze_file(path)
    data = path.read_bytes()

    fmt = report.get("format", "UNKNOWN")
    hdr = report.get("header", {})
    image_base = int(hdr.get("image_base", 0) or 0)
    sections = report.get("sections", [])

    runtime = fingerprint_runtime(data, report)
    is_go = any("Go (" in r for r in runtime)
    api_behaviors = classify_api_behaviors(report, is_go=is_go)
    archive_info = inspect_archive(data)
    wasm_info = inspect_wasm(data) if fmt == "WASM" else None
    main_flow: dict[str, Any] | None = None

    # For ZIP/APK archives, avoid noisy raw-compressed-byte scans
    if fmt == "ZIP":
        crypto_hits: list[dict[str, Any]] = []
        embedded_magic: list[dict[str, Any]] = []
        entropy_blobs: list[dict[str, Any]] = []
        code_scan: dict[str, Any] = {"anomalies": [], "main_candidate": None}
        interesting_strings: list[dict[str, Any]] = []
        if archive_info and archive_info.get("kind") == "Android APK":
            report["file"]["format"] = "APK"
            report["file"]["magic_description"] = "Android APK Package (ZIP container)"
            fmt = "APK"
            crypto_hits = archive_info.get("dex_crypto", [])
            interesting_strings = archive_info.get("dex_strings", [])
    else:
        crypto_hits = scan_crypto_constants(data, sections, image_base, fmt)
        embedded_magic = scan_embedded_magic(data, sections, image_base, fmt)
        crypto_ranges = [
            (int(c["offset"]), int(c["offset"]) + int(c.get("size", 16)))
            for c in crypto_hits
        ]
        entropy_blobs = find_entropy_blobs(
            data,
            sections,
            image_base,
            fmt,
            exclude_ranges=crypto_ranges,
        )
        if is_go and entropy_blobs:
            entropy_blobs = annotate_go_blob_xrefs(data, report, entropy_blobs)
        code_scan = scan_code_anomalies(data, report, is_go=is_go)
        main_flow = analyze_main_flow(data, report, code_scan.get("main_candidate"))
        interesting_strings = extract_strings(
            data,
            sections=sections,
            image_base=image_base,
            fmt=fmt,
            min_len=5,
            only_interesting=True,
        )

    # Pre-entry hooks (ELF .init_array > 1 entry, PE TLS Callbacks)
    init_functions: list[int] = report.get("init_functions", [])
    tls_callbacks: list[int] = report.get("tls_callbacks", [])

    # Compute prioritized tactical leads ("Next Recon Leads")
    leads: list[str] = []
    if is_go:
        go_user_funcs = [
            s for s in report.get("symbols", [])
            if s.get("table") == ".gopclntab" and s.get("name", "").startswith("main.")
        ]
        if go_user_funcs:
            preview = ", ".join(f"{s['name']} (0x{s['value']:x})" for s in go_user_funcs[:5])
            leads.append(f"Go user functions recovered from gopclntab ({len(go_user_funcs)}): {preview}")
    if tls_callbacks:
        cb_str = ", ".join(f"0x{a:x}" for a in tls_callbacks[:4])
        leads.append(f"PE TLS Callback(s) at {cb_str} — executes BEFORE Entry Point!")
    if len(init_functions) >= 2:
        # First entry is typically GCC frame_dummy; additional entries are custom constructors
        extra = ", ".join(f"0x{a:x}" for a in init_functions[1:5])
        leads.append(f"ELF .init_array has {len(init_functions)} constructors (custom pre-main: {extra})")
    if code_scan.get("main_candidate"):
        leads.append(
            f"Stripped ELF main() candidate at {code_scan['main_candidate']} "
            "(resolved via _start -> __libc_start_main)"
        )
    if main_flow and main_flow.get("inline_hints"):
        for ih in main_flow["inline_hints"]:
            leads.append(f"Inline logic inside main(): {ih}")
    for b in api_behaviors:
        if b["severity"] == "HIGH":
            leads.append(f"{b['category']}: {', '.join(b['symbols'][:6])}")
    for mn, cnt in code_scan.get("anomaly_counts", {}).items():
        leads.append(f"Executable code contains {cnt}x `{mn}` instruction(s)")

    # Nanomites / Trap-driven control flow heuristic
    trap_total = sum(code_scan.get("anomaly_counts", {}).get(k, 0) for k in ("int3", "ud2", "int"))
    has_sig_or_fork = any(
        b["category"] in ("Signal / Exception Obfuscation", "Process / Execution / Network")
        for b in api_behaviors
    )
    if trap_total >= 2 or (trap_total >= 1 and has_sig_or_fork):
        leads.append("Possible Nanomites / trap-based control flow obfuscation (int3/ud2 + handler/fork)")

    if code_scan.get("indirect_jumps"):
        leads.append(
            f"Indirect jump table / register branch ({len(code_scan['indirect_jumps'])}x) — potential switch or custom VM dispatcher"
        )
    if crypto_hits:
        names = ", ".join(dict.fromkeys(c["name"] for c in crypto_hits[:4]))
        leads.append(f"Crypto/encoding constant(s) detected: {names}")
    if entropy_blobs:
        top = entropy_blobs[0]
        vstr = f" (vaddr 0x{top['vaddr']:x})" if top["vaddr"] else ""
        leads.append(
            f"High-entropy blob ({top['entropy']:.2f}) at 0x{top['offset']:x}..0x{top['end']:x}"
            f"{vstr} in {top['section']} ({top['size']} B) — inspect for encrypted shellcode/payload"
        )
    if embedded_magic:
        first = embedded_magic[0]
        leads.append(
            f"Embedded {first['type']} signature at offset 0x{first['offset']:x} ({first['section']})"
        )
    if wasm_info and wasm_info.get("exports"):
        leads.append(f"WASM exported functions: {', '.join(wasm_info['exports'][:8])}")
    if archive_info:
        if archive_info["packer_hints"]:
            for ph in archive_info["packer_hints"]:
                leads.append(f"Archive/APK packer: {ph}")
        nested = archive_info.get("nested_apk")
        if nested:
            leads.append(
                f"Nested Android APK inside archive: {nested['source_entry']} "
                f"({len(nested['dex_files'])} DEX, {len(nested['native_libs'])} native .so)"
            )
            for ph in nested.get("packer_hints", []):
                leads.append(f"Nested APK packer: {ph}")

    return {
        "file": report["file"],
        "format": fmt,
        "header": hdr,
        "mitigations": report.get("mitigations", {}),
        "runtime_fingerprint": runtime,
        "pre_entry_hooks": {
            "init_array": [f"0x{a:x}" for a in init_functions],
            "tls_callbacks": [f"0x{a:x}" for a in tls_callbacks],
        },
        "main_flow": main_flow,
        "tactical_leads": leads,
        "api_behaviors": api_behaviors,
        "code_scan": code_scan,
        "crypto_constants": crypto_hits,
        "entropy_blobs": entropy_blobs[:15],
        "embedded_magic": embedded_magic[:15],
        "interesting_strings": interesting_strings[:40],
        "archive": archive_info,
        "wasm": wasm_info,
        "hints": report.get("hints", []),
        "warnings": report.get("warnings", []),
    }
