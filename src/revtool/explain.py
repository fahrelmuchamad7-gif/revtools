"""Penjelasan hasil analisis recon berbahasa Indonesia untuk revtool."""

from __future__ import annotations

from typing import Any

from revtool.display import Theme, render_phase_header


def _note(theme: Theme, label: str, text: str) -> str:
    return f"  {theme.badge_step()} {theme.cyan('[' + label + ']')} {text}"


def explain_recon(recon: dict[str, Any], theme: Theme, phase: int = 5) -> str:
    """Hasilkan penjelasan menyeluruh berbahasa Indonesia atas semua temuan recon."""
    lines: list[str] = [render_phase_header(phase, "Penjelasan", theme)]
    f = recon.get("file", {})
    fmt = recon.get("format", "UNKNOWN")
    hdr = recon.get("header", {})
    mits = recon.get("mitigations", {})
    file_path = f.get("path", "./file")
    entropy = float(f.get("entropy", 0.0))

    # 1. Identitas & Entropi
    if fmt in ("ELF", "PE", "MACH-O"):
        bits = hdr.get("bits", "?")
        arch = hdr.get("architecture", "?")
        os_name = "Linux ELF" if fmt == "ELF" else ("Windows PE" if fmt == "PE" else "macOS/iOS Mach-O")
        ent_desc = (
            "sangat tinggi (indikasi kuat packing/kompresi/enkripsi)"
            if entropy >= 7.2
            else ("agak tinggi (kemungkinan ada blok data padat/terkompresi di .rodata/.data)" if entropy >= 6.2 else "normal untuk kode biner")
        )
        fat_note = ""
        if hdr.get("fat_architectures"):
            fat_note = f" Universal/Fat binary berisi slice [{', '.join(hdr['fat_architectures'])}]."
        lines.append(
            _note(
                theme,
                "Target",
                f"Biner {os_name} {bits}-bit berarsitektur {arch} dengan Entry Point di 0x{int(hdr.get('entry_point', 0)):x} "
                f"dan entropi keseluruhan {entropy:.2f}/8.00 ({ent_desc}).{fat_note}",
            )
        )
    elif fmt in ("APK", "ZIP"):
        arch = recon.get("archive") or {}
        target_arch = arch.get("nested_apk") if arch.get("nested_apk") else arch
        if target_arch and target_arch.get("kind") == "Android APK":
            dex_list = ", ".join(target_arch.get("dex_files", [])) or "tidak ditemukan"
            so_count = len(target_arch.get("native_libs", []))
            packers = target_arch.get("packer_hints", [])
            src_info = (
                f"di dalam arsip ZIP (entry `{target_arch['source_entry']}`)"
                if target_arch.get("source_entry")
                else "langsung sebagai paket Android APK"
            )
            lines.append(
                _note(
                    theme,
                    "Target APK",
                    f"Terdeteksi paket aplikasi Android {src_info} dengan {target_arch.get('total_entries', 0)} entri "
                    f"(Manifest: {'ada' if target_arch.get('has_manifest') else 'tidak ada'}, DEX: {dex_list}, library native .so di lib/: {so_count}).",
                )
            )
            if packers:
                lines.append(
                    _note(
                        theme,
                        "Packer APK",
                        f"Ditemukan protektor mobile: {'; '.join(packers)}. "
                        "Artinya isi kelas Java/Kotlin di classes.dex kemungkinan besar masih berupa stub/terenkripsi dan baru didekode saat runtime oleh library native .so; "
                        "Manifest tetap bisa dibaca (apktool) untuk melihat Activity, Provider, dan skema deeplink.",
                    )
                )
            else:
                lines.append(
                    _note(
                        theme,
                        "Analisis APK",
                        "Tidak terdeteksi packer komersial; ekstrak APK lalu dekompilasi classes.dex dengan jadx-gui dan periksa AndroidManifest.xml.",
                    )
                )
            if target_arch.get("mobile_framework"):
                fw = target_arch["mobile_framework"]
                if fw.get("engine") == "Hermes":
                    lines.append(
                        _note(
                            theme,
                            "React Native / Hermes",
                            f"Aplikasi dibuat dengan React Native menggunakan Hermes Bytecode (HBC v{fw.get('version', '')}). "
                            f"Logika utama aplikasi berada di file bundle `{fw.get('bundle', 'assets/index.android.bundle')}` dan BUKAN di classes.dex! "
                            "Gunakan tool seperti `hbctool` atau `hermes-dec` untuk membongkar bytecode Hermes, atau cari string flag langsung di file bundle.",
                        )
                    )
                elif fw.get("engine") == "Flutter":
                    lines.append(
                        _note(
                            theme,
                            "Flutter AOT",
                            "Aplikasi dibuat dengan framework Flutter. Logika Dart dikompilasi AOT ke dalam library native `libapp.so`. "
                            "Gunakan `reFlutter` atau `flutter-re-tools` untuk merekonstruksi simbol Dart dari snapshot AOT.",
                        )
                    )
                elif fw.get("engine") == "Unity":
                    lines.append(
                        _note(
                            theme,
                            "Unity IL2CPP",
                            "Game/aplikasi Unity menggunakan engine IL2CPP. Kode C# dikompilasi ke library native `libil2cpp.so`. "
                            "Gunakan `Il2CppDumper` bersama file `assets/bin/Data/Managed/Metadata/global-metadata.dat` untuk mengekstrak simbol dan method.",
                        )
                    )
                elif fw.get("engine") == "Cordova":
                    lines.append(
                        _note(
                            theme,
                            "Webview Mobile",
                            "Aplikasi dibungkus dengan Cordova/Capacitor. Kode sumber JavaScript/HTML terletak di folder `assets/www/`.",
                        )
                    )
            if target_arch.get("manifest_components"):
                lines.append(
                    _note(
                        theme,
                        "Komponen Manifest",
                        f"String komponen/URI yang terbaca di AndroidManifest.xml: {', '.join(target_arch['manifest_components'][:6])}.",
                    )
                )
            if target_arch.get("native_elf_checks"):
                for nelf in target_arch["native_elf_checks"]:
                    beh_list = [b["category"] for b in nelf["behaviors"]]
                    beh_txt = ", ".join(beh_list) if beh_list else "tidak ada API sensitif menonjol"
                    lines.append(
                        _note(
                            theme,
                            "Native .so",
                            f"Library `{nelf['entry']}` ({nelf['arch']}, {nelf['stripped']}) menunjukkan aktivitas: {beh_txt}.",
                        )
                    )
            if recon.get("crypto_constants"):
                cnames = ", ".join(dict.fromkeys(c["name"] for c in recon["crypto_constants"]))
                lines.append(_note(theme, "Kripto DEX", f"Konstanta yang ditemukan di DEX: {cnames}."))
            if recon.get("interesting_strings"):
                lines.append(
                    _note(
                        theme,
                        "String DEX",
                        f"Ditemukan {len(recon['interesting_strings'])} string menarik di DEX (lihat tabel High-Signal Strings di atas).",
                    )
                )
            return "\n".join(lines)
        else:
            lines.append(
                _note(
                    theme,
                    "Arsip ZIP",
                    f"File berupa arsip ZIP dengan {arch.get('total_entries', 0)} entri (entropi {entropy:.2f}/8.00). "
                    "Ekstrak arsipnya terlebih dahulu lalu jalankan `revtool recon` pada file biner/script di dalamnya.",
                )
            )
            return "\n".join(lines)
    elif fmt == "HERMES":
        lines.append(
            _note(
                theme,
                "Hermes Bytecode",
                f"File adalah React Native Hermes Bytecode (HBC) dengan entropi {entropy:.2f}/8.00. "
                "Logika JavaScript telah dikompilasi menjadi bytecode Hermes. Gunakan `hbctool` atau `hermes-dec` untuk membongkarnya.",
            )
        )
    elif fmt == "V8_CACHE":
        lines.append(
            _note(
                theme,
                "V8 Bytecode / NW.js",
                f"File teridentifikasi sebagai V8 Bytecode Cache / NW.js Snapshot (`nwjc`) dengan entropi {entropy:.2f}/8.00. "
                "Kode sumber JavaScript telah diubah menjadi snapshot V8 internal. Periksa string tabel dengan `revtool strings -i`, "
                "atau jalankan dengan NW.js (`nw .`) dan pasang DevTools debugger via flag `--remote-debugging-port=9222`.",
            )
        )
    else:
        lines.append(
            _note(
                theme,
                "Target",
                f"File teridentifikasi sebagai {fmt} ({f.get('magic_description', '-')}) dengan entropi {entropy:.2f}/8.00.",
            )
        )

    # 2. Pre-Entry Hooks & Simbol & main()
    pre_hooks = recon.get("pre_entry_hooks", {})
    if pre_hooks.get("tls_callbacks"):
        lines.append(
            _note(
                theme,
                "TLS Callback",
                f"Terdeteksi PE TLS Callback ({', '.join(pre_hooks['tls_callbacks'][:4])})! Kode ini dieksekusi Windows SEBELUM Entry Point (OEP) — sering dipakai untuk anti-debug atau dekripsi awal.",
            )
        )
    if len(pre_hooks.get("init_array", [])) >= 2:
        lines.append(
            _note(
                theme,
                "Constructor Pre-Main",
                f"Section `.init_array` memiliki {len(pre_hooks['init_array'])} fungsi constructor yang dijalankan SEBELUM `main()` (periksa di Ghidra sebelum langsung percaya pada isi `main()`).",
            )
        )

    stripped = str(mits.get("Stripped", ""))
    main_cand = recon.get("code_scan", {}).get("main_candidate")
    if "Yes" in stripped:
        msg = "Biner sudah di-strip (nama fungsi internal dihapus, sehingga di Ghidra/IDA muncul sebagai FUN_.../sub_...)."
        if main_cand:
            msg += (
                f" Kandidat fungsi `main()` berhasil dilacak di {main_cand} melalui pola `_start -> __libc_start_main`; "
                f"langsung lompat ke alamat ini di Ghidra atau jalankan `revtool disasm {file_path} -a {main_cand} -c 40`."
            )
        lines.append(_note(theme, "Simbol & main()", msg))
    elif "No" in stripped:
        lines.append(
            _note(
                theme,
                "Simbol",
                f"Simbol fungsi masih utuh (tidak di-strip). Cek daftar fungsinya lewat `revtool symbols {file_path} --type FUNC`.",
            )
        )

    main_flow = recon.get("main_flow")
    if main_flow and (main_flow.get("calls") or main_flow.get("inline_hints")):
        parts = []
        if main_flow.get("inline_hints"):
            parts.append(f"logika awal: {', '.join(main_flow['inline_hints'])}")
        if main_flow.get("calls"):
            parts.append(f"memanggil: {', '.join(main_flow['calls'][:8])}")
        lines.append(
            _note(
                theme,
                "Alur main()",
                f"Pelacakan statis `main()` ({main_flow['address']}) -> {'; '.join(parts)}.",
            )
        )
    dlang_cand = recon.get("dlang_main_candidate")
    if dlang_cand:
        lines.append(
            _note(
                theme,
                "Dlang _Dmain",
                f"Biner ditulis dalam bahasa D (Dlang). Logika utama crackme berada di fungsi `_Dmain` pada alamat {dlang_cand}. "
                f"Langsung lompat ke alamat ini di Ghidra atau jalankan `revtool disasm {file_path} -a {dlang_cand} -c 40`. "
                "Simbol internal D menggunakan awalan mangling `_D...`.",
            )
        )

    # 3. Hardening / Checksec
    if mits:
        summary_mits = ", ".join(f"{k}: {v}" for k, v in list(mits.items())[:4])
        lines.append(_note(theme, "Proteksi", f"Ringkasan checksec -> {summary_mits}."))

    # 4. API Behaviors (skip GO_RUNTIME-only boilerplate warnings)
    behaviors = recon.get("api_behaviors", [])
    non_go_syms = {
        s.lower()
        for b in behaviors
        if b.get("severity") != "GO_RUNTIME"
        for s in b.get("symbols", [])
    }
    if any(b.get("severity") == "GO_RUNTIME" for b in behaviors):
        lines.append(
            _note(
                theme,
                "Go Runtime",
                f"API seperti VirtualAlloc/mmap/ExceptionHandler/cpuid pada biner Go adalah boilerplate runtime Go. Lihat fungsi user dengan `revtool symbols {file_path} -f main.`.",
            )
        )
    if recon.get("go_concurrency"):
        lines.append(
            _note(
                theme,
                "Go Concurrency",
                "Program memanfaatkan goroutines dan channels (`chan`) untuk komunikasi data dan pemrosesan paralel "
                "(terdeteksi runtime `makechan`, `chansend`, `chanrecv`). Dalam challenge crackme, alur pengiriman/penerimaan channel "
                "sering membagi karakter flag ke worker thread terpisah.",
            )
        )
    if any(k in non_go_syms for k in ("mmap", "mmap64", "mprotect", "virtualalloc", "virtualprotect", "memfd_create")):
        lines.append(
            _note(
                theme,
                "Memori Dinamis",
                "Terdapat pemanggilan mmap/mprotect/VirtualAlloc/memfd_create: program mengalokasikan atau mengubah izin memori saat runtime — pola khas loader, self-decrypting shellcode, atau unpacker.",
            )
        )
    if any(k in non_go_syms for k in ("ptrace", "prctl", "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess")):
        lines.append(
            _note(
                theme,
                "Anti-Debug",
                "Terdapat API ptrace/prctl/IsDebuggerPresent/NtQueryInformationProcess: program kemungkinan membatasi atau mendeteksi proses debugging (mis. PR_SET_DUMPABLE atau ptrace check).",
            )
        )
    if any(k in non_go_syms for k in ("signal", "sigaction", "rt_sigaction", "addvectoredexceptionhandler", "setunhandledexceptionfilter")):
        lines.append(
            _note(
                theme,
                "Signal/Exception",
                "Program mendaftarkan custom signal/exception handler: bila dipasangkan dengan instruksi trap (hlt/ud2/int3), handler tersebut bisa dipakai sebagai pengalih alur kontrol.",
            )
        )
    if "fork" in non_go_syms:
        lines.append(
            _note(
                theme,
                "Multi-Proses",
                "Program memanggil fork() untuk membuat child process (sering dipakai memisahkan proses validator atau teknik anti-debug parent-child).",
            )
        )

    # 5. Anomali Instruksi
    ep = hdr.get("entry_point")
    anomalies = recon.get("code_scan", {}).get("anomalies", [])
    if anomalies and ep is not None:
        crt_hlts = [a for a in anomalies if a["mnemonic"] == "hlt" and 0 <= (int(a["address"], 16) - int(ep)) <= 64]
        other_anomalies = [a for a in anomalies if a not in crt_hlts]
        if crt_hlts and not other_anomalies:
            lines.append(
                _note(
                    theme,
                    "Instruksi hlt",
                    "Satu instruksi `hlt` di dekat _start merupakan pengaman CRT normal bawaan compiler GCC setelah __libc_start_main, bukan jebakan anti-analisis.",
                )
            )
        elif other_anomalies:
            mn_list = ", ".join(dict.fromkeys(f"{a['mnemonic']}@{a['address']}" for a in other_anomalies))
            lines.append(
                _note(
                    theme,
                    "Anomali Kode",
                    f"Ditemukan instruksi tidak lazim di section executable ({mn_list}) yang patut dicurigai sebagai trap signal / Nanomites, anti-debug, atau syscall langsung.",
                )
            )
    if recon.get("code_scan", {}).get("indirect_jumps"):
        lines.append(
            _note(
                theme,
                "Dispatcher / Switch",
                "Terdeteksi lompatan tidak langsung (`jmp [reg]` / `jmp reg`) di luar PLT — pola umum tabel switch besar, state machine, atau Custom VM dispatcher.",
            )
        )
    if recon.get("wasm"):
        w = recon["wasm"]
        lines.append(
            _note(
                theme,
                "WASM",
                f"Modul WebAssembly dengan {len(w.get('sections', []))} section dan {len(w.get('exports', []))} fungsi export; konversi ke .wat memakai `wasm2wat` (wabt) untuk membaca logikanya.",
            )
        )

    # 6. Kripto, Magic Tertanam, & Blob Entropi
    crypto_hits = recon.get("crypto_constants", [])
    if crypto_hits:
        desc_list = ", ".join(
            f"{c['name']} di 0x{c['offset']:x} ({c['section']})" for c in crypto_hits[:4]
        )
        lines.append(
            _note(
                theme,
                "Kripto",
                f"Terdeteksi konstanta algoritma/checksum standar: {desc_list}. Lacak XREF ke alamat tersebut di Ghidra untuk menemukan fungsi pemrosesnya.",
            )
        )

    magic_hits = recon.get("embedded_magic", [])
    if magic_hits:
        m_desc = ", ".join(f"{m['type']}@0x{m['offset']:x} ({m['section']})" for m in magic_hits[:4])
        lines.append(
            _note(
                theme,
                "Payload Tertanam",
                f"Ditemukan signature stream/file tertanam: {m_desc}. Periksa area tersebut di Ghidra atau uji potong via `revtool xform`.",
            )
        )

    blobs = recon.get("entropy_blobs", [])
    if blobs:
        top = blobs[0]
        user_blobs = [b for b in blobs if b.get("xref_main")]
        if user_blobs:
            ub = user_blobs[0]
            xref_msg = f" Blob milik user terdeteksi direferensikan oleh {', '.join(ub['xref_main'][:3])} di 0x{ub['offset']:x}..0x{ub['end']:x}."
        elif "xref_label" in top:
            xref_msg = " Seluruh blob di atas tidak memiliki XREF dari `main.*` (kemungkinan besar tabel internal runtime/stdlib Go)."
        else:
            xref_msg = ""
        lines.append(
            _note(
                theme,
                "Blob Entropi",
                f"Terdapat {len(blobs)} area byte padat/acak (tertinggi di 0x{top['offset']:x}..0x{top['end']:x}, {top['section']}, entropi {top['entropy']:.2f})."
                f"{xref_msg} Gunakan `revtool blobs {file_path}` untuk daftar lengkap atau `revtool xform` untuk uji dekode.",
            )
        )

    if recon.get("interesting_strings"):
        lines.append(
            _note(
                theme,
                "String Penting",
                f"Terdapat {len(recon['interesting_strings'])} string bertag recon. Gunakan `revtool strings {file_path} -i` untuk melihat semuanya.",
            )
        )

    return "\n".join(lines)


def explain_subcommand(command: str, context: dict[str, Any], theme: Theme) -> str:
    """Hasilkan catatan penjelasan berbahasa Indonesia untuk subcommand."""
    notes: dict[str, str] = {
        "triage": "Ringkasan struktur biner (identitas file, header ELF/PE, status proteksi, tabel section + entropi, dan ringkasan import).",
        "info": "Detail metadata file, hash (MD5/SHA-1/SHA-256), header arsitektur, Entry Point, dan flag mitigasi biner.",
        "sections": "Daftar section beserta VAddr, Offset file, ukuran, izin RWX, dan entropi (section >= 7.20 atau RWX perlu diperiksa lebih lanjut).",
        "segments": "Daftar Program Header ELF yang memetakan offset file ke alamat virtual memori saat biner dijalankan.",
        "imports": "Daftar library eksternal dan simbol/API yang di-import; gunakan `-f <kata>` untuk menyaring API tertentu.",
        "symbols": "Daftar simbol internal (.symtab/.dynsym atau Export PE); gunakan `-t FUNC` untuk fungsi saja.",
        "disasm": "Disassembly instruksi mesin dari Entry Point, `--section`, atau `--addr` menggunakan Capstone.",
        "strings": "Ekstraksi string ASCII/UTF-16 beserta offset, VAddr, section, dan tag recon; gunakan `-i` untuk menyaring string bertag saja.",
        "crypto": "Hasil pemindaian konstanta kripto standar (AES, SHA, MD5, CRC32, TEA, ChaCha20, Base64) serta header Zlib/file tertanam.",
        "blobs": "Lokasi area byte berentropi tinggi dan signature file tertanam; atur ambang batas dengan `-t <nilai>` bila perlu.",
        "xform": (
            "Belum ada opsi slice/transformasi diberikan sehingga seluruh file ditampilkan apa adanya."
            if context.get("no_ops")
            else "Hasil pemotongan dan transformasi byte statis beserta deteksi format output."
        ),
    }
    text = notes.get(command)
    if not text:
        return ""
    return "\n" + _note(theme, "Penjelasan", text)
