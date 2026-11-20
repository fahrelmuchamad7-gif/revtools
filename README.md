# revtool (REVTOOLS CLI)

Toolkit CLI berbahasa Indonesia untuk recon statis, inspeksi biner, dan *disassembly* pada tantangan Reverse Engineering CTF tingkat nasional maupun internasional (**ELF / PE / Mach-O / APK / WASM**).  
Berjalan **100% offline** tanpa API AI dan dirancang nyaman dipakai di terminal Kali Linux maupun Windows.

---

## Fitur Utama

- **`revtool audit <file>`** — **Audit Kerentanan Statis Biner & Pemetaan CWE:**
  - Pemindaian otomatis fungsi rentan / berbahaya: **CWE-120 / CWE-242** (`gets`, `strcpy`, `strcat`, `sprintf`), **CWE-134** (Format String dinamis via analisis register `rdi`/stack), **CWE-78** (OS Command Injection via `system`, `popen`), **CWE-338** (Weak PRNG `rand`/`srand` dengan catatan prediktabilitas CTF), **CWE-732** (Izin memori RWX via `mprotect`/`VirtualProtect` atau section statis), dan **CWE-770** (`alloca`).
  - **Korelasi Hardening Checksec:** Eskalasi severity otomatis ke **CRITICAL** bila fungsi buffer overflow terdeteksi pada biner tanpa Stack Canary.
  - Catatan triage reverse engineering (lokasi offset stack, Saved RIP, format specifier leak `%p`/`%x`/`%n`) dan rekomendasi remediasi defensif.
- **`revtool recon <file>`** — **Recon Statis Lengkap Bertahap (`Phase 1`–`5`) + Penjelasan Bahasa Indonesia:**
  - **Deteksi & Pelacakan Otomatis `main()` Multi-Arsitektur (`main_finder`):** Resolusi presisi fungsi `main()` utama bahkan pada biner *stripped* (ELF x86_64 non-PIE `mov rdi` & PIE `lea rdi`, ELF x86 32-bit `push`, ELF AArch64 ARM64 `adrp+add`, ARM 32-bit `ldr r0`, Windows PE CRT Startup dispatch, Mach-O `LC_MAIN`, Go `main.main`, Rust `crate::main`, dan Dlang `_Dmain`).
  - *Fingerprinting* bahasa/runtime/packer: **D (Dlang)** (`_Dmain` + LDC/DMD), **Go** (`gopclntab` hingga 500k simbol + deteksi versi `go1.xx` & filter runtime), **Rust**, **Zig**, **Nim**, **PyInstaller** (+ versi Python), **.NET**, **UPX / suspek custom packer**, **V8 Code Cache / NW.js snapshot** (`nwjc`), serta **React Native Hermes Bytecode** (`.hbc`).
  - **Go Concurrency & Channels:** Deteksi otomatis pemrosesan konkuren/goroutines via `chan` (`makechan`, `chansend`, `chanrecv`, `selectgo`).
  - **Pre-Entry Hooks:** Deteksi *PE TLS Callbacks* (dieksekusi sebelum Entry Point) dan *ELF `.init_array` constructors* (dieksekusi sebelum `main()`).
  - **Pelacakan Statis `main()` & Resolusi PLT:** Mencari kandidat `main()` pada biner *stripped*, auto-resolusi `_Dmain` pada biner Dlang, memulihkan fungsi user Go (`main.*`), meresolusi panggilan `@plt`, referensi string `.rodata`/`.rdata`, serta konstanta inline (seperti FNV-1a).
  - **Perilaku API & Anomali Kode:** Pengelompokan API mencurigakan (`mmap`/`mprotect`/RWX, `ptrace`/`prctl`, `signal`/`sigaction`, `fork`), pemindaian instruksi anomali (`hlt`, `ud2`, `int3`, `rdtsc`, `cpuid`, `syscall`), indikasi **Nanomites**, dan *indirect jump* (kandidat `switch` / *VM dispatcher*).
  - **Kripto, Blob Entropi, & Magic Tertanam:** Deteksi konstanta AES, SHA-1/256/512, MD5, CRC32, TEA/XTEA, Blowfish, ChaCha20/Salsa20, SipHash, Base64/32/58, Zlib tervalidasi, serta penandaan XREF `main.*` vs `stdlib/runtime` pada blob biner Go.
  - **Inspeksi Mobile Framework & WebAssembly:** Pemindaian Android APK (`AndroidManifest.xml`, `classes*.dex`, analisis ELF pada `.so`, deteksi packer seperti `DPT-Shell`, `Jiagu`, `Bangcle`), deteksi framework mobile (**React Native dengan Hermes Bytecode HBC v96+**, **Flutter Dart AOT `libapp.so`**, **Unity IL2CPP**, **Cordova/Capacitor**), serta modul WebAssembly (`.wasm`).
- **`revtool triage <file>`** — Ringkasan cepat struktur file, hash, header, proteksi (`checksec`), tabel section + entropi, dan ringkasan import.
- **`revtool info <file>`** — Detail file, hash (MD5/SHA-1/SHA-256), header arsitektur, Entry Point, dan status mitigasi.
- **`revtool sections <file>`** — Tabel section (`VAddr`, `Offset`, `Size`, izin `RWX`, dan *Shannon entropy*).
- **`revtool segments <file>`** — Daftar *Program Header* ELF atau segmen Mach-O.
- **`revtool imports <file>`** — Daftar library eksternal yang ditautkan dan fungsi yang di-import (`-f` filter, `-l` batas).
- **`revtool symbols <file>`** — Tabel simbol ELF (`.symtab`/`.dynsym`/`.gopclntab`), export PE, atau simbol Mach-O (`-f`, `-t FUNC`, `-l`).
- **`revtool disasm <file>`** — Disassembly via Capstone pada Entry Point, `--section`, atau `--addr` (dukung `--raw` / `--asm-only` untuk pipe bersih).
- **`revtool strings <file>`** — Ekstraksi string ASCII & UTF-16LE dengan offset, VAddr, section, dan tag recon (`FLAG_FMT` termasuk `CJ{...}`, `CRACKME_UI`, `SECRET`, `DLANG_SYM`, `URL`, `IP`, `BASE64_CAND`, `HEX_BLOB`, `CRYPTO`, `ANTI_DBG`, `EXEC_IO`, `PATH`).
- **`revtool crypto <file>`** — Pemindai konstanta kripto standar dan signature file/Zlib tertanam.
- **`revtool blobs <file>`** — Pencari area byte berentropi tinggi (*sliding window*) lengkap dengan XREF `main.*` untuk biner Go.
- **`revtool xform <file>`** — Alat bantu transformasi byte statis di terminal (`--section`, `--offset`, `--length`, `--swap`, `--rol`, `--ror`, `--word-size`, `--xor`, `--unhex`, `--b64d`, `--out`).
- Flag global di semua subcommand: `--json`, `--no-color`, `--no-banner`, `--no-explain`, `-V`/`--version`, `-h`/`--help`.

---

## Referensi Open-Source yang Digunakan

Repo referensi yang di-clone lokal di `references/` (diabaikan oleh git) dan library Python yang terpasang bersama `revtool`:

- [`eliben/pyelftools`](https://github.com/eliben/pyelftools) — Parser ELF & DWARF Python.
- [`erocarrera/pefile`](https://github.com/erocarrera/pefile) — Parser Portable Executable (PE) Python.
- [`capstone-engine/capstone`](https://github.com/capstone-engine/capstone) — *Disassembly engine* multi-arsitektur untuk `disasm` dan analisis kode `recon`.
- [`slimm609/checksec`](https://github.com/slimm609/checksec) — Referensi pengecekan mitigasi keamanan biner (`RELRO`, `Canary`, `NX`, `PIE`).

---

## Cara Instalasi di Kali Linux (WSL / Native)

```bash
git clone https://github.com/fahrelmuchamad7-gif/revtools.git
cd revtools
python3 -m venv ~/.local/share/revtool-venv
~/.local/share/revtool-venv/bin/pip install -e .
mkdir -p ~/.local/bin
ln -sf ~/.local/share/revtool-venv/bin/revtool ~/.local/bin/revtool
```

Pastikan `~/.local/bin` sudah masuk ke `PATH` (misalnya di `~/.bashrc` atau `~/.zshrc`), lalu jalankan dari direktori mana saja:

```bash
revtool --help
revtool recon ./challenge
revtool audit ./challenge
revtool sections ./challenge
revtool strings ./challenge -i
revtool crypto ./challenge
revtool blobs ./challenge
revtool disasm ./challenge -a 0x11c0 -c 30
revtool disasm ./challenge -a 0x11c0 -c 30 --raw
revtool xform ./challenge -o 0x2019 -n 0x100 --rol 8 --xor CYB
```

---

## Menjalankan Pengujian (Unit Test)

```bash
python -m unittest discover -s tests -v
```
