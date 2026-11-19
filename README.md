# revtool (REVTOOLS CLI)

Command-line binary reconnaissance, static inspection, and disassembly toolkit built for Linux / Kali terminals and national-level CTF Reverse Engineering challenges (ELF / PE / Mach-O / APK / WASM).

## Features

- `revtool recon <file>` — **Deep CTF RE Reconnaissance** dengan laporan bertahap & penjelasan berbahasa Indonesia: compiler/runtime/packer fingerprinting (Go + versi, Rust, Zig, Nim, PyInstaller + versi Python, .NET, UPX / custom packer), pre-entry hooks (PE TLS Callbacks & ELF `.init_array`), `main()` static trace (PLT call resolution, string refs, inline hash/cipher constants), suspicious API behavior categorization, trap/anti-debug/Nanomites & indirect jump (VM dispatcher) scan, crypto constants (AES, SHA-1/256/512, MD5, CRC32, TEA/XTEA, Blowfish, ChaCha20, SipHash, Base64/32/58), high-entropy blob localization, WASM module inspection, and Android APK / ZIP packer recon (`DPT-Shell`, `Jiagu`, `Bangcle`, `Flutter`, `IL2CPP`, Manifest + native `.so` inspection).
- `revtool triage <file>` — One-shot triage dashboard with `REVTOOLS` banner, hashes, header, hardening flags, sections + Shannon entropy, and import/symbol summary.
- `revtool strings <file>` — Context-aware ASCII & UTF-16LE string extractor mapped to file offset, VAddr, and section name, with automatic recon tags (`FLAG_FMT`, `URL`, `IP`, `BASE64_CAND`, `HEX_BLOB`, `CRYPTO`, `ANTI_DBG`, `EXEC_IO`, `PATH`).
- `revtool crypto <file>` — Scans for AES S-Box/InvSBox/Te0, SHA-256/SHA-1/MD5 constants, CRC32 tables, TEA/XTEA delta, ChaCha20/Salsa20 sigma, Base64/32/58 alphabets, and embedded file signatures.
- `revtool blobs <file>` — Sliding-window Shannon entropy scanner to pinpoint encrypted/compressed shellcode or hidden data blobs with exact file ranges and virtual addresses.
- `revtool xform <file>` — Static byte slice & transform helper (`--section`, `--offset`, `--length`, `--rol`, `--ror`, `--swap`, `--xor`, `--unhex`, `--b64d`, `--out`) for testing hypotheses quickly in the terminal.
- `revtool disasm <file>` — Multi-architecture disassembly at entry point, `--section`, or `--addr` powered by Capstone (use `--raw` / `--asm-only` for clean pipe output).
- `revtool info | sections | segments | imports | symbols <file>` — Focused structural ELF/PE inspection.
- `--json` flag on every subcommand for scripting and piping to `jq`.

## GitHub Reference Tools & Libraries

Local reference repositories cloned under `references/` (ignored by git) and Python packages installed alongside `revtool`:

- [`eliben/pyelftools`](https://github.com/eliben/pyelftools) — Pure-Python ELF and DWARF parser (also provides `readelf.py`).
- [`erocarrera/pefile`](https://github.com/erocarrera/pefile) — Standard Python Portable Executable (PE) parser.
- [`capstone-engine/capstone`](https://github.com/capstone-engine/capstone) — Lightweight multi-architecture disassembly engine powering `revtool disasm` and `recon` instruction anomaly scanning.
- [`slimm609/checksec`](https://github.com/slimm609/checksec) — Reference binary security mitigation checker (`RELRO`, `Canary`, `NX`, `PIE`, `FORTIFY`).

## Installation on Kali Linux (WSL / Native)

```bash
python3 -m venv ~/.local/share/revtool-venv
~/.local/share/revtool-venv/bin/pip install -e .
mkdir -p ~/.local/bin
ln -sf ~/.local/share/revtool-venv/bin/revtool ~/.local/bin/revtool
```

Make sure `~/.local/bin` is in your `PATH`, then run `revtool` from anywhere:

```bash
revtool --help
revtool recon ./challenge
revtool strings ./challenge --interesting
revtool crypto ./challenge
revtool blobs ./challenge
revtool disasm ./challenge --count 25
revtool xform ./challenge --offset 0x2019 --length 0x1d58 --rol 8 --xor CYB --b64d
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```
