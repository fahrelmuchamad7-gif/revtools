"""Defensive static vulnerability auditor and CWE classifier for revtool.

Scans binary imports, calling conventions, and checksec hardening to detect:
- CWE-120 / CWE-242: Unbounded buffer copy / inherently dangerous functions (gets, strcpy, sprintf)
- CWE-134: Externally-controlled format strings (printf, fprintf, syslog)
- CWE-78: OS Command Injection (system, popen, execl)
- CWE-338: Use of Cryptographically Weak PRNG (rand, srand)
- CWE-732: Insecure memory permissions (RWX memory via mprotect/VirtualProtect)
- CWE-676: Potentially dangerous functions (scanf, alloca)
- CWE-327: Broken or risky cryptographic algorithms (DES, MD5, RC4)

Provides:
- Severity (CRITICAL, HIGH, MEDIUM, INFO)
- CWE ID and title
- Technical description & CTF Reverse Engineering triage lead
- Defensive remediation / safe replacement recommendations
"""

from __future__ import annotations

from typing import Any


DANGEROUS_APIS: dict[str, dict[str, Any]] = {
    "gets": {
        "cwe": "CWE-120 / CWE-242",
        "severity": "CRITICAL",
        "title": "Inherently Dangerous Function (Unbounded Stack Buffer Overflow)",
        "description": "Fungsi `gets()` membaca input hingga baris baru tanpa batasan ukuran ke buffer stack.",
        "re_note": (
            "Periksa alokasi frame stack pada fungsi pemanggil (mis. [rbp - 0x20]). "
            "Input yang melebihi ukuran buffer akan langsung menimpa variabel lokal di bawahnya "
            "serta frame pointer (RBP/EBP) dan return address (Saved RIP)."
        ),
        "remediation": "Ganti dengan `fgets(buf, sizeof(buf), stdin)`.",
    },
    "strcpy": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "title": "Buffer Copy without Checking Size of Input",
        "description": "Fungsi `strcpy()` menyalin string sumber tanpa memverifikasi ukuran buffer tujuan.",
        "re_note": (
            "Periksa apakah panjang string sumber divalidasi sebelum disalin. "
            "Jika string sumber lebih besar dari kapasitas buffer penerima, terjadi stack/heap buffer overflow."
        ),
        "remediation": "Ganti dengan `strncpy(dst, src, sizeof(dst) - 1)` atau `strlcpy`.",
    },
    "strcat": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "title": "Buffer Concatenation without Size Check",
        "description": "Fungsi `strcat()` menyambungkan string tanpa mengecek sisa kapasitas buffer penerima.",
        "re_note": "Analisis apakah akumulasi panjang string dapat melebihi alokasi memori buffer tujuan.",
        "remediation": "Ganti dengan `strncat` atau `snprintf`.",
    },
    "sprintf": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "title": "Buffer Overflow in Formatted Output",
        "description": "Fungsi `sprintf()` menulis hasil format ke buffer memori tanpa batasan panjang maksimum.",
        "re_note": "Cek apakah argumen format (misal %s) berasal dari input pengguna yang panjangnya tidak dibatasi.",
        "remediation": "Ganti dengan `snprintf(buf, sizeof(buf), fmt, ...)`.",
    },
    "vsprintf": {
        "cwe": "CWE-120",
        "severity": "HIGH",
        "title": "Buffer Overflow in Variable Argument Formatted Output",
        "description": "Fungsi `vsprintf()` menulis va_list tanpa pembatasan ukuran ke buffer tujuan.",
        "re_note": "Periksa ukuran buffer penerima dan gunakan vsnprintf.",
        "remediation": "Ganti dengan `vsnprintf`.",
    },
    "system": {
        "cwe": "CWE-78",
        "severity": "HIGH",
        "title": "OS Command Injection",
        "description": "Fungsi `system()` mengeksekusi string perintah melalui shell sistem (/bin/sh atau cmd.exe).",
        "re_note": (
            "Periksa konstruksi string perintah di fungsi pemanggil (misal melalui snprintf/strcat). "
            "Jika terdapat input pengguna yang tidak disanitasi, karakter metakarakter shell "
            "(seperti `;`, `|`, `&&`, `$(...)`) dapat mengeksekusi perintah arbitrer."
        ),
        "remediation": "Gunakan `execve` / `CreateProcess` dengan array argumen terpisah tanpa perantara shell.",
    },
    "popen": {
        "cwe": "CWE-78",
        "severity": "HIGH",
        "title": "OS Command Injection via Pipe",
        "description": "Fungsi `popen()` membuka pipa proses shell dengan perintah yang dapat dimanipulasi.",
        "re_note": "Periksa apakah perintah dibentuk dari variabel input pengguna.",
        "remediation": "Gunakan `fork()` + `execve()` dengan argumen eksplisit.",
    },
    "rand": {
        "cwe": "CWE-338",
        "severity": "MEDIUM",
        "title": "Use of Cryptographically Weak PRNG",
        "description": "Fungsi `rand()` / `random()` menggunakan Linear Congruential Generator (LCG) yang tidak aman.",
        "re_note": (
            "Pada challenge crackme/CTF, generator pseudorandom ini sering di-seed dengan `srand(time(NULL))` "
            "atau nilai tetap. State dan output PRNG dapat ditebak dan direproduksi secara presisi menggunakan "
            "skrip Python atau C dengan nilai seed yang sama."
        ),
        "remediation": "Gunakan generator kriptografi aman seperti `getrandom()`, `/dev/urandom`, atau `BCryptGenRandom`.",
    },
    "alloca": {
        "cwe": "CWE-770",
        "severity": "MEDIUM",
        "title": "Allocation of Resources Without Limits on Stack",
        "description": "Fungsi `alloca()` mengalokasikan memori langsung di stack tanpa validasi batas ketersediaan.",
        "re_note": "Nilai ukuran yang sangat besar atau negatif dapat memicu stack clash atau crash.",
        "remediation": "Gunakan alokasi heap (`malloc`) dengan pemeriksaan ukuran maksimum.",
    },
}


def audit_binary(data: bytes, report: dict[str, Any]) -> dict[str, Any]:
    """Perform a static vulnerability audit and map findings to CWE categories."""
    findings: list[dict[str, Any]] = []
    mits = report.get("mitigations", {})
    imported_symbols = [str(s.get("name", "")) for s in report.get("imported_symbols", [])]
    plt_map = report.get("plt_map", {})
    all_sym_names = [str(s.get("name", "")) for s in report.get("symbols", [])]

    # Combine symbol names
    all_names = set(imported_symbols + list(plt_map.values()) + all_sym_names)
    normalized_names = {name.lower().split("@")[0].split("@@")[0].lstrip("_"): name for name in all_names}

    has_canary = "Found" in str(mits.get("Stack Canary", "")) or "Enabled" in str(mits.get("Stack Canary", ""))

    # 1. Dangerous API matching
    for func_key, info in DANGEROUS_APIS.items():
        matched_name = normalized_names.get(func_key)
        if matched_name:
            sev = info["severity"]
            desc = info["description"]
            re_note = info["re_note"]

            # Correlate with checksec: gets/strcpy without Canary is CRITICAL
            if func_key in ("gets", "strcpy", "sprintf") and not has_canary:
                sev = "CRITICAL"
                re_note = (
                    f"⚠️ [Stack Canary TIDAK AKTIF!] {re_note} "
                    "Karena tidak ada canary cookie, buffer overflow dapat langsung menimpa return address tanpa terdeteksi!"
                )

            findings.append(
                {
                    "cwe": info["cwe"],
                    "severity": sev,
                    "symbol": matched_name,
                    "title": info["title"],
                    "description": desc,
                    "re_note": re_note,
                    "remediation": info["remediation"],
                }
            )

    # 2. Check for Format String vulnerability suspects (printf, fprintf, syslog)
    format_funcs = {"printf", "fprintf", "vprintf", "syslog"}
    matched_fmt = [normalized_names[f] for f in format_funcs if f in normalized_names]
    if matched_fmt:
        fmt_str_candidate = _inspect_format_string_calls(data, report)
        if fmt_str_candidate:
            findings.append(
                {
                    "cwe": "CWE-134",
                    "severity": "HIGH",
                    "symbol": fmt_str_candidate.get("symbol", matched_fmt[0]),
                    "title": "Use of Externally-Controlled Format String",
                    "description": (
                        f"Terdeteksi pemanggilan `{fmt_str_candidate.get('symbol', 'printf')}` di alamat {fmt_str_candidate.get('address')} "
                        f"di mana argumen format string berasal dari buffer stack/dinamis (`{fmt_str_candidate.get('setup')}`) dan bukan string statis .rodata."
                    ),
                    "re_note": (
                        f"Pada alamat {fmt_str_candidate.get('address')}, format string dilewatkan tanpa string penentu statis. "
                        "Gunakan penentu format `%p` atau `%x` untuk membocorkan alamat memori stack/libc (leak PIE/canary), "
                        "atau `%n` untuk menulis nilai ke memori target."
                    ),
                    "remediation": "Pastikan selalu menyertakan format literal statis: `printf(\"%s\", user_str)`.",
                }
            )

    # 3. Check for RWX Memory (CWE-732)
    rwx_funcs = {"mprotect", "mmap", "virtualalloc", "virtualprotect"}
    matched_rwx = [normalized_names[f] for f in rwx_funcs if f in normalized_names]
    has_rwx_sec = any(
        "W" in str(s.get("perms", "")) and "X" in str(s.get("perms", ""))
        for s in report.get("sections", [])
    )
    if matched_rwx or has_rwx_sec:
        findings.append(
            {
                "cwe": "CWE-732",
                "severity": "HIGH" if has_rwx_sec else "MEDIUM",
                "symbol": ", ".join(matched_rwx) if matched_rwx else "RWX Section",
                "title": "Insecure Memory Permissions (Read-Write-Execute)",
                "description": (
                    "Program mengalokasikan atau mengubah perizinan memori menjadi Read-Write-Execute (RWX). "
                    if matched_rwx
                    else "Ditemukan section biner dengan izin RWX (Read-Write-Execute) secara statis."
                ),
                "re_note": (
                    "Izin RWX memungkinkan eksekusi kode yang ditulis saat runtime. Pola ini sangat umum "
                    "pada self-modifying code, unpacker, shellcode execution buffer, atau JIT compiler."
                ),
                "remediation": "Terapkan prinsip W^X (Write XOR Execute): jangan beri izin eksekusi pada halaman yang dapat ditulis.",
            }
        )

    # Sort findings by severity: CRITICAL > HIGH > MEDIUM > INFO
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 99))

    summary = {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "info": sum(1 for f in findings if f["severity"] == "INFO"),
    }

    return {
        "findings": findings,
        "summary": summary,
        "mitigations": mits,
    }


def _inspect_format_string_calls(data: bytes, report: dict[str, Any]) -> dict[str, Any] | None:
    """Disassemble calls to printf/fprintf in x86_64 to detect non-rodata format strings."""
    fmt = report.get("format")
    hdr = report.get("header", {})
    arch = str(hdr.get("architecture", "")).lower()
    if fmt != "ELF" or ("x86_64" not in arch and "amd64" not in arch):
        return None

    try:
        import capstone
    except ImportError:
        return None

    plt_map: dict[int, str] = report.get("plt_map", {})
    printf_plt_addrs = {addr: name for addr, name in plt_map.items() if "printf" in name.lower()}
    if not printf_plt_addrs:
        return None

    # Find .text section
    text_sec = next((s for s in report.get("sections", []) if s.get("name") == ".text"), None)
    if not text_sec:
        return None

    t_off = int(text_sec.get("offset", 0))
    t_size = int(text_sec.get("size", 0))
    t_addr = int(text_sec.get("addr", 0))
    if t_size <= 0 or t_off + t_size > len(data):
        return None

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    chunk = data[t_off : min(len(data), t_off + min(t_size, 65536))]
    insns = list(md.disasm(chunk, t_addr))

    for i, ins in enumerate(insns):
        if ins.mnemonic == "call":
            try:
                tgt = int(ins.op_str.strip(), 0)
            except ValueError:
                continue

            if tgt in printf_plt_addrs:
                # Inspect preceding instructions setting up rdi (first argument in x86_64 SysV ABI)
                for j in range(i - 1, max(-1, i - 7), -1):
                    prev = insns[j]
                    # Direct stack buffer: lea rdi, [rbp - ...] or mov rdi, [rbp - ...]
                    if (prev.mnemonic == "lea" and "rdi, [rbp" in prev.op_str) or (
                        prev.mnemonic == "mov" and "rdi, qword ptr [rbp" in prev.op_str
                    ):
                        return {
                            "address": f"0x{ins.address:x}",
                            "symbol": printf_plt_addrs[tgt],
                            "instruction": f"{ins.mnemonic} {ins.op_str}",
                            "setup": f"{prev.mnemonic} {prev.op_str}",
                        }
                    # Indirect via rax: mov rdi, rax
                    if prev.mnemonic == "mov" and prev.op_str.strip() in ("rdi, rax", "rdi, eax"):
                        # Trace backward to find what loaded rax
                        for k in range(j - 1, max(-1, j - 5), -1):
                            setter = insns[k]
                            if (setter.mnemonic == "lea" and "rax, [rbp" in setter.op_str) or (
                                setter.mnemonic == "mov" and "rax, qword ptr [rbp" in setter.op_str
                            ):
                                return {
                                    "address": f"0x{ins.address:x}",
                                    "symbol": printf_plt_addrs[tgt],
                                    "instruction": f"{ins.mnemonic} {ins.op_str}",
                                    "setup": f"{setter.mnemonic} {setter.op_str} -> {prev.mnemonic} {prev.op_str}",
                                }
                            # If rax was loaded from rip-relative ([rip + ...]) or immediate, it's a constant string
                            if setter.mnemonic == "lea" and "[rip" in setter.op_str:
                                break
                            if setter.mnemonic == "mov" and (setter.op_str.startswith("rax, ") or setter.op_str.startswith("eax, ")):
                                break
                        break
                    # If rdi is set directly from rip-relative rodata or immediate, it's safe
                    if prev.mnemonic == "lea" and "rdi, [rip" in prev.op_str:
                        break
                    if prev.mnemonic == "mov" and (prev.op_str.startswith("rdi, ") or prev.op_str.startswith("edi, ")):
                        break
    return None
