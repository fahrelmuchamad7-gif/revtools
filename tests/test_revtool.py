"""Tests for revtool ELF/PE parsers and CLI subcommands."""

from __future__ import annotations

import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from revtool.cli import main
from revtool.parsers import analyze_file


def _build_minimal_elf64() -> bytes:
    """Construct a valid synthetic ELF64 binary with segments, sections, dynamic, and dynsym."""
    # Layout:
    # 0x000..0x040: ELF64 Header (64 bytes)
    # 0x040..0x120: 4 Program Headers (4 * 56 = 224 bytes) -> ends at 0x120
    # 0x120..0x140: .interp string ("/lib64/ld-linux-x86-64.so.2\x00") (28 bytes)
    # 0x140..0x160: .text bytes (32 bytes)
    # 0x160..0x1a0: .dynstr ("\x00libc.so.6\x00printf\x00__stack_chk_fail\x00main\x00")
    # 0x1a0..0x200: .dynsym (4 * 24 = 96 bytes)
    # 0x200..0x240: .dynamic (4 * 16 = 64 bytes)
    # 0x240..0x290: .shstrtab
    # 0x2a0..0x460: 7 Section Headers (7 * 64 = 448 bytes)

    buf = bytearray(0x460)

    interp_bytes = b"/lib64/ld-linux-x86-64.so.2\x00"
    buf[0x120 : 0x120 + len(interp_bytes)] = interp_bytes

    text_bytes = b"\x55\x48\x89\xe5\x48\x83\xec\x10\xb8\x00\x00\x00\x00\xc9\xc3" + b"\x90" * 17
    buf[0x140 : 0x140 + len(text_bytes)] = text_bytes

    dynstr = b"\x00libc.so.6\x00printf\x00__stack_chk_fail\x00main\x00"
    buf[0x160 : 0x160 + len(dynstr)] = dynstr
    # Offsets in dynstr:
    # libc.so.6 -> 1
    # printf -> 11
    # __stack_chk_fail -> 18
    # main -> 35

    # .dynsym entries (24 bytes each: st_name, st_info, st_other, st_shndx, st_value, st_size)
    # 0: null
    struct.pack_into("<IBBHQQ", buf, 0x1A0 + 0, 0, 0, 0, 0, 0, 0)
    # 1: printf (GLOBAL=1 << 4 | FUNC=2 -> 0x12), UND (0)
    struct.pack_into("<IBBHQQ", buf, 0x1A0 + 24, 11, 0x12, 0, 0, 0, 0)
    # 2: __stack_chk_fail (GLOBAL FUNC, UND)
    struct.pack_into("<IBBHQQ", buf, 0x1A0 + 48, 18, 0x12, 0, 0, 0, 0)
    # 3: main (GLOBAL FUNC, section 2 (.text), addr 0x401140, size 15)
    struct.pack_into("<IBBHQQ", buf, 0x1A0 + 72, 35, 0x12, 0, 2, 0x401140, 15)

    # .dynamic entries (16 bytes each: d_tag, d_val)
    # DT_NEEDED = 1 (libc.so.6 = 1)
    struct.pack_into("<qQ", buf, 0x200 + 0, 1, 1)
    # DT_FLAGS = 30, DF_BIND_NOW = 0x8
    struct.pack_into("<qQ", buf, 0x200 + 16, 30, 0x8)
    # DT_FLAGS_1 = 0x6FFFFFFB, DF_1_PIE = 0x08000000
    struct.pack_into("<qQ", buf, 0x200 + 32, 0x6FFFFFFB, 0x08000000)
    # DT_NULL = 0
    struct.pack_into("<qQ", buf, 0x200 + 48, 0, 0)

    shstrtab = b"\x00.interp\x00.text\x00.dynstr\x00.dynsym\x00.dynamic\x00.shstrtab\x00"
    buf[0x240 : 0x240 + len(shstrtab)] = shstrtab
    # Offsets in shstrtab:
    # .interp -> 1
    # .text -> 9
    # .dynstr -> 15
    # .dynsym -> 23
    # .dynamic -> 31
    # .shstrtab -> 40

    # ELF64 Header (64 bytes)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    buf[0:16] = e_ident
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        buf,
        16,
        3,       # ET_DYN
        62,      # x86_64
        1,       # EV_CURRENT
        0x1140,  # e_entry
        0x40,    # e_phoff
        0x2A0,   # e_shoff
        0,       # e_flags
        64,      # e_ehsize
        56,      # e_phentsize
        4,       # e_phnum
        64,      # e_shentsize
        7,       # e_shnum
        6,       # e_shstrndx
    )

    # Program Headers at 0x40 (4 * 56 bytes)
    # 0: PT_LOAD (R-X)
    struct.pack_into("<IIQQQQQQ", buf, 0x40 + 0 * 56, 1, 5, 0, 0, 0, 0x2A0, 0x2A0, 0x1000)
    # 1: PT_INTERP (R--)
    struct.pack_into("<IIQQQQQQ", buf, 0x40 + 1 * 56, 3, 4, 0x120, 0x120, 0x120, len(interp_bytes), len(interp_bytes), 1)
    # 2: PT_GNU_STACK (RW-)
    struct.pack_into("<IIQQQQQQ", buf, 0x40 + 2 * 56, 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    # 3: PT_GNU_RELRO (R--)
    struct.pack_into("<IIQQQQQQ", buf, 0x40 + 3 * 56, 0x6474E552, 4, 0x200, 0x200, 0x200, 0x40, 0x40, 1)

    # Section Headers at 0x2A0 (7 * 64 bytes)
    sh_fmt = "<IIQQQQIIQQ"
    # 0: NULL
    struct.pack_into(sh_fmt, buf, 0x2A0 + 0 * 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    # 1: .interp (PROGBITS=1, ALLOC=2)
    struct.pack_into(sh_fmt, buf, 0x2A0 + 1 * 64, 1, 1, 2, 0x120, 0x120, len(interp_bytes), 0, 0, 1, 0)
    # 2: .text (PROGBITS=1, ALLOC|EXECINSTR=6)
    struct.pack_into(sh_fmt, buf, 0x2A0 + 2 * 64, 9, 1, 6, 0x1140, 0x140, len(text_bytes), 0, 0, 16, 0)
    # 3: .dynstr (STRTAB=3, ALLOC=2)
    struct.pack_into(sh_fmt, buf, 0x2A0 + 3 * 64, 15, 3, 2, 0x160, 0x160, len(dynstr), 0, 0, 1, 0)
    # 4: .dynsym (DYNSYM=11, ALLOC=2, link=3)
    struct.pack_into(sh_fmt, buf, 0x2A0 + 4 * 64, 23, 11, 2, 0x1A0, 0x1A0, 96, 3, 1, 8, 24)
    # 5: .dynamic (DYNAMIC=6, ALLOC|WRITE=3, link=3)
    struct.pack_into(sh_fmt, buf, 0x2A0 + 5 * 64, 31, 6, 3, 0x200, 0x200, 64, 3, 0, 8, 16)
    # 6: .shstrtab (STRTAB=3)
    struct.pack_into(sh_fmt, buf, 0x2A0 + 6 * 64, 40, 3, 0, 0, 0x240, len(shstrtab), 0, 0, 1, 0)

    return bytes(buf)


def _build_minimal_pe64() -> bytes:
    """Construct a valid synthetic PE32+ (64-bit) binary with sections, imports, and exports."""
    buf = bytearray(0x600)

    # DOS Header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 0x80

    # PE Signature + COFF Header at 0x80
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        buf,
        0x84,
        0x8664,  # AMD64
        2,       # NumberOfSections
        1700000000,
        0,
        0,
        240,     # SizeOfOptionalHeader (PE32+ standard = 240)
        0x0022,  # Executable + LargeAddressAware
    )

    # Optional Header PE32+ at 0x98
    opt_off = 0x98
    struct.pack_into("<H", buf, opt_off, 0x20B)  # PE32+
    struct.pack_into("<I", buf, opt_off + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", buf, opt_off + 24, 0x140000000)  # ImageBase
    struct.pack_into("<H", buf, opt_off + 68, 3)  # Subsystem: Windows CUI
    struct.pack_into("<H", buf, opt_off + 70, 0x4160)  # DllCharacteristics: HighEntropyVA | DynamicBase | NXCompat | GuardCF
    struct.pack_into("<I", buf, opt_off + 108, 16)  # NumberOfRvaAndSizes

    # Data Directories at opt_off + 112:
    # 0: Export Table -> RVA 0x2080, size 0x80
    struct.pack_into("<II", buf, opt_off + 112 + 0 * 8, 0x2080, 0x80)
    # 1: Import Table -> RVA 0x2000, size 0x40
    struct.pack_into("<II", buf, opt_off + 112 + 1 * 8, 0x2000, 0x40)

    # Section Headers at 0x98 + 240 = 0x188
    sec_off = opt_off + 240
    # 0: .text (RVA 0x1000, raw 0x300, size 0x100, RX CODE)
    struct.pack_into("<8sIIIIIIHHI", buf, sec_off + 0, b".text\x00\x00\x00", 0x100, 0x1000, 0x100, 0x300, 0, 0, 0, 0, 0x60000020)
    # 1: .rdata (RVA 0x2000, raw 0x400, size 0x200, R INIT_DATA)
    struct.pack_into("<8sIIIIIIHHI", buf, sec_off + 40, b".rdata\x00\x00", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040)

    # .text data at 0x300
    buf[0x300:0x304] = b"\x48\x31\xc0\xc3"

    # .rdata at raw 0x400 (maps to RVA 0x2000)
    # Import Directory at RVA 0x2000 (raw 0x400):
    # Descriptor 0: ILT RVA 0x2028, Name RVA 0x2040, IAT RVA 0x2028
    struct.pack_into("<IIIII", buf, 0x400, 0x2028, 0, 0, 0x2040, 0x2028)
    # Descriptor 1: null terminator at 0x414
    # ILT at RVA 0x2028 (raw 0x428): 64-bit thunk pointing to Hint/Name at RVA 0x2050, then 0
    struct.pack_into("<QQ", buf, 0x428, 0x2050, 0)
    # DLL Name at RVA 0x2040 (raw 0x440)
    buf[0x440 : 0x440 + 13] = b"KERNEL32.dll\x00"
    # Hint/Name at RVA 0x2050 (raw 0x450): 2-byte hint + "ExitProcess\x00"
    struct.pack_into("<H", buf, 0x450, 0)
    buf[0x452 : 0x452 + 12] = b"ExitProcess\x00"

    # Export Directory at RVA 0x2080 (raw 0x480):
    # Base=1, NumberOfFunctions=1, NumberOfNames=1,
    # AddressOfFunctions=0x20B0, AddressOfNames=0x20B4, AddressOfNameOrdinals=0x20B8
    struct.pack_into("<IIHHIIIIIII", buf, 0x480, 0, 0, 0, 0, 0x20C0, 1, 1, 1, 0x20B0, 0x20B4, 0x20B8)
    struct.pack_into("<I", buf, 0x4B0, 0x1000)  # func RVA
    struct.pack_into("<I", buf, 0x4B4, 0x20CC)  # name RVA
    struct.pack_into("<H", buf, 0x4B8, 0)       # ordinal index 0
    buf[0x4C0 : 0x4C0 + 11] = b"sample.dll\x00"
    buf[0x4CC : 0x4CC + 10] = b"HelloFunc\x00"

    return bytes(buf)


class TestRevtool(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.elf_path = self.root / "test_elf64"
        self.elf_path.write_bytes(_build_minimal_elf64())
        self.pe_path = self.root / "test_pe64.exe"
        self.pe_path.write_bytes(_build_minimal_pe64())
        self.txt_path = self.root / "notes.txt"
        self.txt_path.write_text("hello reverse engineering\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_analyze_elf64(self) -> None:
        report = analyze_file(self.elf_path)
        self.assertEqual(report["format"], "ELF")
        self.assertEqual(report["header"]["class"], "ELF64")
        self.assertEqual(report["header"]["architecture"], "x86_64 (AMD64)")
        self.assertEqual(report["header"]["entry_point"], 0x1140)
        self.assertEqual(report["header"]["interpreter"], "/lib64/ld-linux-x86-64.so.2")

        mits = report["mitigations"]
        self.assertEqual(mits["PIE"], "Enabled (PIE)")
        self.assertEqual(mits["NX"], "Enabled")
        self.assertEqual(mits["RELRO"], "Full RELRO")
        self.assertEqual(mits["Stack Canary"], "Found")

        sec_names = [s["name"] for s in report["sections"]]
        self.assertIn(".text", sec_names)
        self.assertIn(".dynsym", sec_names)
        self.assertEqual(report["needed_libraries"], ["libc.so.6"])

        imp_names = [s["name"] for s in report["imported_symbols"]]
        self.assertIn("printf", imp_names)
        self.assertIn("__stack_chk_fail", imp_names)

        exp_names = [s["name"] for s in report["exports"]]
        self.assertIn("main", exp_names)

    def test_analyze_pe64(self) -> None:
        report = analyze_file(self.pe_path)
        self.assertEqual(report["format"], "PE")
        self.assertEqual(report["header"]["class"], "PE32+")
        self.assertEqual(report["header"]["architecture"], "x86_64 (AMD64)")
        self.assertEqual(report["header"]["entry_point"], 0x140001000)

        mits = report["mitigations"]
        self.assertEqual(mits["ASLR (DynamicBase)"], "Enabled")
        self.assertEqual(mits["DEP (NXCompat)"], "Enabled")
        self.assertEqual(mits["CFG (Control Flow Guard)"], "Enabled")

        self.assertEqual(report["needed_libraries"], ["KERNEL32.dll"])
        imp_names = [s["name"] for s in report["imported_symbols"]]
        self.assertEqual(imp_names, ["ExitProcess"])

        exp_names = [s["name"] for s in report["exports"]]
        self.assertEqual(exp_names, ["HelloFunc"])

    def test_analyze_plain_text(self) -> None:
        report = analyze_file(self.txt_path)
        self.assertEqual(report["format"], "TEXT")
        self.assertEqual(report["sections"], [])

    def test_cli_subcommands_and_json(self) -> None:
        for cmd in ("triage", "info", "sections", "segments", "imports", "symbols"):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = main([cmd, str(self.elf_path), "--no-color"])
            self.assertEqual(rc, 0)
            self.assertTrue(len(out.getvalue().strip()) > 0)

        # JSON output check
        out_json = io.StringIO()
        with redirect_stdout(out_json):
            rc = main(["info", str(self.pe_path), "--json"])
        self.assertEqual(rc, 0)
        parsed = json.loads(out_json.getvalue())
        self.assertEqual(parsed["format"], "PE")
        self.assertEqual(parsed["header"]["class"], "PE32+")

        # Filter check on imports
        out_flt = io.StringIO()
        with redirect_stdout(out_flt):
            rc = main(["imports", str(self.elf_path), "--filter", "print", "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("printf", out_flt.getvalue())
        self.assertNotIn("__stack_chk_fail", out_flt.getvalue())

        # Logo banner check on triage
        out_banner = io.StringIO()
        with redirect_stdout(out_banner):
            rc = main(["triage", str(self.elf_path), "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("Static Binary Triage & RE Toolkit", out_banner.getvalue())

        # Disasm check (requires capstone)
        out_dis = io.StringIO()
        with redirect_stdout(out_dis):
            rc = main(["disasm", str(self.elf_path), "--count", "6", "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("push", out_dis.getvalue())
        self.assertIn("ret", out_dis.getvalue())

    def test_recon_crypto_strings_blobs_and_xform(self) -> None:
        import base64
        import os
        import zipfile
        from revtool.crypto_scan import AES_SBOX_HEAD, TEA_DELTA_LE
        from revtool.xform import rotate_words, xor_bytes

        # 1. Craft a binary-like payload with AES S-Box, TEA delta, flag string, and high-entropy blob
        blob = bytes((i * 73 + 19) & 0xFF for i in range(256))
        # Ensure high entropy using os.urandom
        rand_blob = os.urandom(256)
        payload = (
            b"\x00" * 32
            + AES_SBOX_HEAD
            + b"\x00" * 16
            + TEA_DELTA_LE
            + b"\x00" * 16
            + b"https://ctf.example.org/api\x00"
            + b"CTF{static_recon_test}\x00"
            + rand_blob
        )
        bin_path = self.root / "recon_sample.bin"
        bin_path.write_bytes(payload)

        # crypto command
        out_crypto = io.StringIO()
        with redirect_stdout(out_crypto):
            rc = main(["crypto", str(bin_path), "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("AES S-Box", out_crypto.getvalue())
        self.assertIn("TEA/XTEA Delta", out_crypto.getvalue())

        # strings --interesting
        out_str = io.StringIO()
        with redirect_stdout(out_str):
            rc = main(["strings", str(bin_path), "--interesting", "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("FLAG_FMT", out_str.getvalue())
        self.assertIn("URL", out_str.getvalue())

        # blobs command
        out_blobs = io.StringIO()
        with redirect_stdout(out_blobs):
            rc = main(["blobs", str(bin_path), "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("High-Entropy Regions", out_blobs.getvalue())

        # recon --json on synthetic ELF
        out_recon = io.StringIO()
        with redirect_stdout(out_recon):
            rc = main(["recon", str(self.elf_path), "--json"])
        self.assertEqual(rc, 0)
        recon_data = json.loads(out_recon.getvalue())
        self.assertEqual(recon_data["format"], "ELF")
        self.assertIn("runtime_fingerprint", recon_data)

        # recon on synthetic APK (ZIP with AndroidManifest.xml + libdpt.so)
        apk_path = self.root / "packed.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", b"dex\n035\x00" + os.urandom(200))
            zf.writestr("lib/arm64-v8a/libdpt.so", b"\x7fELF" + b"\x00" * 60)
        out_apk = io.StringIO()
        with redirect_stdout(out_apk):
            rc = main(["recon", str(apk_path), "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("Android APK", out_apk.getvalue())
        self.assertIn("DPT-Shell", out_apk.getvalue())

        # xform pipeline test: reverse(b64 -> xor -> ror8) using rol8 -> xor -> b64d
        plain = b"\x89PNG\r\n\x1a\n" + b"TESTPAYLOAD12345"
        b64 = base64.b64encode(plain)
        xored = xor_bytes(b64, b"KEY")
        obf = rotate_words(xored, 8, word_size=4, left=False)
        obf_path = self.root / "obf.bin"
        obf_path.write_bytes(obf)

        out_xf = io.StringIO()
        with redirect_stdout(out_xf):
            rc = main(["xform", str(obf_path), "--rol", "8", "--xor", "KEY", "--b64d", "--json"])
        self.assertEqual(rc, 0)
        xf_data = json.loads(out_xf.getvalue())
        self.assertEqual(xf_data["detected_format"], "PNG")
        self.assertIn("TESTPAYLOAD12345", xf_data["preview_ascii"])

    def test_indonesian_explanations(self) -> None:
        out_rec = io.StringIO()
        with redirect_stdout(out_rec):
            rc = main(["recon", str(self.elf_path), "--no-color", "--no-banner"])
        self.assertEqual(rc, 0)
        self.assertIn("] Penjelasan", out_rec.getvalue())
        self.assertNotIn("Penjelasan Singkat", out_rec.getvalue())

        out_sec = io.StringIO()
        with redirect_stdout(out_sec):
            rc = main(["sections", str(self.elf_path), "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("[Penjelasan]", out_sec.getvalue())

        out_noexp = io.StringIO()
        with redirect_stdout(out_noexp):
            rc = main(["recon", str(self.elf_path), "--no-color", "--no-banner", "--no-explain"])
        self.assertEqual(rc, 0)
        self.assertNotIn("] Penjelasan", out_noexp.getvalue())

    def test_advanced_ctf_recon_tls_wasm_crypto_and_nanomites(self) -> None:
        from revtool.crypto_scan import SHA512_H_LE, SIPHASH_CONST
        from revtool.recon import run_recon

        # 1. Synthetic WASM module with Export section ("check_flag")
        export_payload = b"\x01\x0acheck_flag\x00\x00"  # 1 export, len=10, "check_flag", func kind=0, idx=0
        wasm_bytes = (
            b"\x00asm\x01\x00\x00\x00"
            + b"\x01\x04\x01\x60\x00\x00"
            + b"\x07" + bytes([len(export_payload)]) + export_payload
        )
        wasm_path = self.root / "chal.wasm"
        wasm_path.write_bytes(wasm_bytes)
        w_rec = run_recon(wasm_path)
        self.assertEqual(w_rec["format"], "WASM")
        self.assertEqual(w_rec["wasm"]["exports"], ["check_flag"])

        # 2. PE32+ with TLS Callback at Data Directory 9
        pe_buf = bytearray(_build_minimal_pe64())
        opt_off = 0x98
        # Data Directory 9 (TLS) -> RVA 0x2100, size 0x28
        struct.pack_into("<II", pe_buf, opt_off + 112 + 9 * 8, 0x2100, 0x28)
        # Raw offset for RVA 0x2100 is 0x400 + 0x100 = 0x500
        # AddressOfCallBacks (offset +24 in TLS64) = VA 0x140002130
        struct.pack_into("<Q", pe_buf, 0x500 + 24, 0x140002130)
        # Callbacks array at raw 0x530: 0x140001000, 0
        struct.pack_into("<QQ", pe_buf, 0x530, 0x140001000, 0)
        pe_tls_path = self.root / "tls_chal.exe"
        pe_tls_path.write_bytes(bytes(pe_buf))
        pe_rec = run_recon(pe_tls_path)
        self.assertEqual(pe_rec["pre_entry_hooks"]["tls_callbacks"], ["0x140001000"])
        self.assertTrue(any("TLS Callback" in lead for lead in pe_rec["tactical_leads"]))

        # 3. SHA-512 + SipHash crypto scan
        c_path = self.root / "crypto_v3.bin"
        c_path.write_bytes(b"\x00" * 16 + SHA512_H_LE + b"\x00" * 16 + SIPHASH_CONST)
        c_rec = run_recon(c_path)
        c_names = {c["name"] for c in c_rec["crypto_constants"]}
        self.assertIn("SHA-512 Init Vector (LE)", c_names)
        self.assertIn("SipHash Initialization String", c_names)

        # 4. Nanomites (multiple int3) + indirect jump (jmp rax = ff e0) in ELF64 .text
        elf_buf = bytearray(_build_minimal_elf64())
        # .text is at raw 0x140, size 32
        elf_buf[0x140 : 0x140 + 6] = b"\xcc\xcc\xff\xe0\xc3\x90"
        nano_path = self.root / "nano_elf"
        nano_path.write_bytes(bytes(elf_buf))
        n_rec = run_recon(nano_path)
        self.assertTrue(any("Nanomites" in lead for lead in n_rec["tactical_leads"]))
        self.assertTrue(len(n_rec["code_scan"]["indirect_jumps"]) >= 1)

    def test_macho64_and_fat_binary_recon_and_disasm(self) -> None:
        from revtool.recon import run_recon

        # Construct a minimal valid Mach-O 64-bit LE x86_64 binary:
        # 0x000..0x020: mach_header_64 (32B)
        # 0x020..0x0B8: LC_SEGMENT_64 (__TEXT, 1 section __text) (72 + 80 = 152B = 0x98)
        # 0x0B8..0x0F0: LC_LOAD_DYLIB ("/usr/lib/libSystem.B.dylib\x00") (56B = 0x38)
        # 0x0F0..0x108: LC_SYMTAB (24B)
        # 0x108..0x120: LC_MAIN (24B)
        # sizeofcmds = 0x100 (256B)
        # 0x140..0x160: __text code bytes (entryoff = 0x140)
        # 0x180..0x1A0: nlist_64 (2 * 16 = 32B)
        # 0x1A0..0x1D0: strtab ("\x00_main\x00___stack_chk_fail\x00")
        buf = bytearray(0x200)
        # mach_header_64 (LE): magic 0xfeedfacf, cputype 0x01000007, cpusub 3, filetype 2 (MH_EXECUTE), ncmds 4, sizeofcmds 0x100, flags 0x200000 (MH_PIE)
        struct.pack_into("<IIIIIIII", buf, 0, 0xFEEDFACF, 0x01000007, 3, 2, 4, 0x100, 0x200000, 0)

        # LC_SEGMENT_64 at 0x20 (cmd=0x19, cmdsize=152)
        struct.pack_into("<II", buf, 0x20, 0x19, 152)
        struct.pack_into("<16sQQQQIIII", buf, 0x28, b"__TEXT", 0x100000000, 0x1000, 0, 0x200, 7, 5, 1, 0)
        # Section __text at 0x20 + 72 = 0x68 (80B)
        struct.pack_into("<16s16sQQIIIIIIII", buf, 0x68, b"__text", b"__TEXT", 0x100000140, 16, 0x140, 4, 0, 0, 0x80000400, 0, 0, 0)

        # LC_LOAD_DYLIB at 0xB8 (cmd=0xC, cmdsize=56)
        struct.pack_into("<IIIIII", buf, 0xB8, 0xC, 56, 24, 0, 0, 0)
        dylib = b"/usr/lib/libSystem.B.dylib\x00"
        buf[0xB8 + 24 : 0xB8 + 24 + len(dylib)] = dylib

        # LC_SYMTAB at 0xF0 (cmd=0x2, cmdsize=24)
        struct.pack_into("<IIIIII", buf, 0xF0, 0x2, 24, 0x180, 2, 0x1A0, 0x30)

        # LC_MAIN at 0x108 (cmd=0x80000028, cmdsize=24)
        struct.pack_into("<IIQQ", buf, 0x108, 0x80000028, 24, 0x140, 0)

        # __text code at 0x140: push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        buf[0x140 : 0x140 + 8] = b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3"

        # strtab at 0x1A0: "\x00_main\x00___stack_chk_fail\x00"
        strtab = b"\x00_main\x00___stack_chk_fail\x00"
        buf[0x1A0 : 0x1A0 + len(strtab)] = strtab

        # nlist_64 at 0x180:
        # 0: _main (n_strx=1, N_SECT|N_EXT=0x0f, n_sect=1, n_desc=0, n_value=0x100000140)
        struct.pack_into("<IBBHQ", buf, 0x180, 1, 0x0F, 1, 0, 0x100000140)
        # 1: ___stack_chk_fail (n_strx=7, N_UNDF|N_EXT=0x01, n_sect=0, n_desc=0, n_value=0)
        struct.pack_into("<IBBHQ", buf, 0x190, 7, 0x01, 0, 0, 0)

        macho_path = self.root / "chal_macho"
        macho_path.write_bytes(bytes(buf))

        m_rep = analyze_file(macho_path)
        self.assertEqual(m_rep["format"], "MACH-O")
        self.assertEqual(m_rep["header"]["architecture"], "x86_64 (AMD64)")
        self.assertEqual(m_rep["header"]["entry_point"], 0x100000140)
        self.assertEqual(m_rep["mitigations"]["PIE"], "Enabled (MH_PIE)")
        self.assertEqual(m_rep["mitigations"]["Stack Canary"], "Found")
        self.assertIn("/usr/lib/libSystem.B.dylib", m_rep["needed_libraries"])

        m_rec = run_recon(macho_path)
        self.assertEqual(m_rec["main_flow"]["address"], "0x100000140")

        out_dis = io.StringIO()
        with redirect_stdout(out_dis):
            rc = main(["disasm", str(macho_path), "--count", "5", "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("push", out_dis.getvalue())
        self.assertIn("ret", out_dis.getvalue())

        # Universal / Fat Mach-O wrapper (0xCAFEBABE, 1 arch at offset 0x1000)
        fat_buf = bytearray(0x1000 + len(buf))
        struct.pack_into(">II", fat_buf, 0, 0xCAFEBABE, 1)
        struct.pack_into(">IIIII", fat_buf, 8, 0x01000007, 3, 0x1000, len(buf), 12)
        fat_buf[0x1000:] = buf
        fat_path = self.root / "chal_fat"
        fat_path.write_bytes(bytes(fat_buf))

        fat_rep = analyze_file(fat_path)
        self.assertEqual(fat_rep["format"], "MACH-O")
        self.assertEqual(fat_rep["header"]["fat_architectures"], ["x86_64 (AMD64)"])
        self.assertEqual(fat_rep["header"]["entry_point"], 0x100000140)

    def test_go_gopclntab_filtering_dedup_and_raw_disasm(self) -> None:
        import os
        from revtool.crypto_scan import AES_SBOX_HEAD, scan_crypto_constants, scan_embedded_magic
        from revtool.recon import find_entropy_blobs, run_recon
        from revtool.strings_scan import classify_string

        # 1. Synthetic Go ELF64 with .gopclntab (0xFFFFFFF1) + int3 padding + Go build ID
        elf_buf = bytearray(_build_minimal_elf64())
        # Put 8x int3 (0xcc) padding after ret in .text (0x140 + 15 = 0x14f)
        elf_buf[0x14F : 0x14F + 8] = b"\xcc" * 8

        # Build a valid gopclntab v1.20+ (0xFFFFFFF1) blob to append as extra payload
        # Header: 8B + 8 * 8B = 72B (0x48)
        # funcname table at offset 0x48: "main.main\x00main.checkFlag\x00"
        # ftab at offset 0x80: 2 entries * 8B = 16B + end entry (8B) = 24B -> func structs at ftab + 24 (0x98)
        fnames = b"main.main\x00main.checkFlag\x00"
        pclntab = bytearray(0xD0)
        struct.pack_into("<IHBB", pclntab, 0, 0xFFFFFFF1, 0, 1, 8)
        text_start = 0x1140
        funcname_off = 0x48
        pcln_off = 0x80
        struct.pack_into("<8Q", pclntab, 8, 2, 1, text_start, funcname_off, 0, 0, 0, pcln_off)
        pclntab[funcname_off : funcname_off + len(fnames)] = fnames
        # ftab entries at pcln_off (0x80):
        # entry 0: entryoff=0, funcoff=0x18 (_func at pcln_off + 0x18 = 0x98)
        # entry 1: entryoff=0x10, funcoff=0x20 (_func at pcln_off + 0x20 = 0xa0)
        # sentinel: entryoff=0x20, funcoff=0
        struct.pack_into("<II", pclntab, pcln_off + 0, 0, 0x18)
        struct.pack_into("<II", pclntab, pcln_off + 8, 0x10, 0x20)
        struct.pack_into("<II", pclntab, pcln_off + 16, 0x20, 0)
        # _func 0 at 0x98: entryOff=0, nameOff=0 ("main.main")
        struct.pack_into("<Ii", pclntab, pcln_off + 0x18, 0, 0)
        # _func 1 at 0xA0: entryOff=0x10, nameOff=10 ("main.checkFlag")
        struct.pack_into("<Ii", pclntab, pcln_off + 0x20, 0x10, 10)

        go_bin = bytes(elf_buf) + b"\x00Go build ID: go1.24.0-test\x00" + bytes(pclntab)
        go_path = self.root / "go_chal"
        go_path.write_bytes(go_bin)

        go_rep = analyze_file(go_path)
        go_sym_names = [s["name"] for s in go_rep["symbols"]]
        self.assertIn("main.main", go_sym_names)
        self.assertIn("main.checkFlag", go_sym_names)

        go_rec = run_recon(go_path)
        self.assertTrue(any("go1.24" in r for r in go_rec["runtime_fingerprint"]))
        self.assertTrue(any("main.main" in lead for lead in go_rec["tactical_leads"]))
        self.assertFalse(any("Nanomites" in lead for lead in go_rec["tactical_leads"]))
        self.assertEqual(go_rec["code_scan"]["anomaly_counts"].get("int3", 0), 0)

        # 2. Crypto vs Blobs deduplication: full 256-byte AES S-Box (0x00..0xFF permutation, entropy=8.0)
        sbox_256 = AES_SBOX_HEAD + bytes(b for b in range(256) if b not in AES_SBOX_HEAD)
        dedup_bin = b"\x00" * 32 + sbox_256 + b"\x00" * 32
        hits = scan_crypto_constants(dedup_bin)
        self.assertEqual(hits[0]["name"], "AES S-Box")
        ex_ranges = [(h["offset"], h["offset"] + h["size"]) for h in hits]
        blobs = find_entropy_blobs(dedup_bin, exclude_ranges=ex_ranges)
        self.assertEqual(blobs, [])

        # 3. False-positive Zlib in .pdata filtered out
        fake_pdata = b"\x00" * 32 + b"\x78\x9c\x01\x02\x03\x04\x05\x06\x07\x08"
        secs = [{"name": ".pdata", "offset": 0, "size": len(fake_pdata), "addr": 0x1000}]
        self.assertEqual(scan_embedded_magic(fake_pdata, sections=secs), [])

        # 4. BASE64_CAND excludes Go package paths, detects real Base64
        self.assertNotIn("BASE64_CAND", classify_string("internal/reflectlite"))
        self.assertIn("BASE64_CAND", classify_string("U2VjcmV0RmxhZ0RhdGE="))

        # 5. revtool disasm --raw outputs bare assembly without headers or explanations
        out_raw = io.StringIO()
        with redirect_stdout(out_raw):
            rc = main(["disasm", str(self.elf_path), "--count", "3", "--raw"])
        self.assertEqual(rc, 0)
        raw_text = out_raw.getvalue()
        self.assertNotIn("Disassembly", raw_text)
        self.assertNotIn("[Penjelasan]", raw_text)
        self.assertIn("0x1140: push rbp", raw_text)

        # 6. Go blob XREF tagging: distinguish main.* referenced blob vs stdlib/runtime blob
        # Build Go ELF64 where .text at 0x1140 (vaddr 0x1140) has `lea rax, [rip + 0x100]` -> 0x1247 (inside .rodata/blob)
        # Put a high-entropy blob at 0x1240..0x1340 and another unreferenced high-entropy blob at 0x1400..0x1500
        # First let's construct a clean Go ELF64 with .text (vaddr 0x1140, off 0x140) and .rodata (vaddr 0x2000, off 0x300, size 0x400)
        go_x_buf = bytearray(0x800)
        go_x_buf[0:16] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        # Section headers at 0x600: 4 sections (NULL, .text, .rodata, .shstrtab)
        struct.pack_into("<HHIQQQIHHHHHH", go_x_buf, 16, 3, 62, 1, 0x1140, 0, 0x600, 0, 64, 56, 0, 64, 4, 3)
        # At .text (off 0x140, vaddr 0x1140): `lea rax, [rip + (0x2000 - 0x1147)]` = 0xeb9 -> 48 8d 05 b9 0e 00 00; c3
        struct.pack_into("<3siB", go_x_buf, 0x140, b"\x48\x8d\x05", 0x2000 - 0x1147, 0xC3)
        # .rodata (off 0x300, vaddr 0x2000, size 0x300):
        # 0x300..0x400 -> 256B high-entropy blob (vaddr 0x2000) referenced by main.checkFlag!
        # 0x480..0x580 -> 256B high-entropy blob (vaddr 0x2180) NOT referenced by main.*!
        go_x_buf[0x300:0x400] = bytes(range(256))
        go_x_buf[0x480:0x580] = bytes((b ^ 0xA5) for b in range(256))
        shs = b"\x00.text\x00.rodata\x00.shstrtab\x00"
        go_x_buf[0x5A0 : 0x5A0 + len(shs)] = shs
        sh_fmt = "<IIQQQQIIQQ"
        struct.pack_into(sh_fmt, go_x_buf, 0x600 + 64 * 1, 1, 1, 6, 0x1140, 0x140, 0x20, 0, 0, 16, 0)
        struct.pack_into(sh_fmt, go_x_buf, 0x600 + 64 * 2, 7, 1, 2, 0x2000, 0x300, 0x300, 0, 0, 16, 0)
        struct.pack_into(sh_fmt, go_x_buf, 0x600 + 64 * 3, 15, 3, 0, 0, 0x5A0, len(shs), 0, 0, 1, 0)

        # gopclntab pointing main.checkFlag -> 0x1140 (size 16)
        fnames2 = b"main.checkFlag\x00"
        pc2 = bytearray(0xB0)
        struct.pack_into("<IHBB", pc2, 0, 0xFFFFFFF1, 0, 1, 8)
        struct.pack_into("<8Q", pc2, 8, 1, 1, 0x1140, 0x48, 0, 0, 0, 0x70)
        pc2[0x48 : 0x48 + len(fnames2)] = fnames2
        struct.pack_into("<II", pc2, 0x70, 0, 0x10)
        struct.pack_into("<II", pc2, 0x78, 0x20, 0)
        struct.pack_into("<Ii", pc2, 0x80, 0, 0)

        go_xref_path = self.root / "go_xref_chal"
        go_xref_path.write_bytes(bytes(go_x_buf) + b"\x00Go build ID: go1.24.0\x00" + bytes(pc2))

        gx_rec = run_recon(go_xref_path)
        blobs_gx = gx_rec["entropy_blobs"]
        self.assertTrue(len(blobs_gx) >= 2)
        # First blob must be the main.checkFlag-referenced blob at vaddr 0x2000
        self.assertEqual(blobs_gx[0]["vaddr"], 0x2000)
        self.assertEqual(blobs_gx[0]["xref_main"], ["main.checkFlag"])
        self.assertIn("main.* (main.checkFlag)", blobs_gx[0]["xref_label"])
        # Second blob has no main.* xref -> marked Go stdlib/runtime
        self.assertEqual(blobs_gx[1]["xref_main"], [])
        self.assertIn("Go stdlib/runtime", blobs_gx[1]["xref_label"])

    def test_cyber_jawara_2025_capabilities(self) -> None:
        """Test support for Dlang, Go concurrency, Hermes HBC APK, and V8 snapshot."""
        import zipfile
        from revtool.parsers import analyze_file
        from revtool.recon import run_recon
        from revtool.strings_scan import classify_string

        # 1. New string tags
        self.assertIn("FLAG_FMT", classify_string("CJ{christian-dior-dior_pop_smoke}"))
        self.assertIn("CRACKME_UI", classify_string("validateBtn"))
        self.assertIn("CRACKME_UI", classify_string("CORRECT FLAG"))
        self.assertIn("SECRET", classify_string("rules.json"))
        self.assertIn("SECRET", classify_string("my_secret_token_123"))
        self.assertIn("DLANG_SYM", classify_string("_D4main4mainFZv"))

        # 2. V8 Code Cache / NW.js snapshot (nwjc)
        v8_path = self.root / "chall.bin"
        v8_path.write_bytes(b"\x89\x06\xde\xc0" + b"\x00" * 64 + b"CORRECT FLAG\x00validateBtn\x00")
        v8_rep = analyze_file(v8_path)
        self.assertEqual(v8_rep["format"], "V8_CACHE")
        v8_rec = run_recon(v8_path)
        self.assertTrue(any("V8 Bytecode" in lead for lead in v8_rec["tactical_leads"]))

        # 3. Hermes standalone bytecode file (.hbc / bundle)
        hbc_path = self.root / "index.android.bundle"
        hbc_buf = bytearray(64)
        struct.pack_into("<QI", hbc_buf, 0, 0x1F1903C103BC1FC6, 96)
        hbc_path.write_bytes(bytes(hbc_buf))
        hbc_rep = analyze_file(hbc_path)
        self.assertEqual(hbc_rep["format"], "HERMES")
        hbc_rec = run_recon(hbc_path)
        self.assertTrue(any("Hermes" in r for r in hbc_rec["runtime_fingerprint"]))

        # 4. React Native Hermes APK framework detection
        apk_path = self.root / "hermes_test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x00" * 32 + b"MainActivity")
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
            zf.writestr("assets/index.android.bundle", bytes(hbc_buf))
            zf.writestr("lib/arm64-v8a/libhermes.so", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        apk_rec = run_recon(apk_path)
        self.assertIsNotNone(apk_rec["archive"].get("mobile_framework"))
        self.assertIn("Hermes Bytecode HBC v96", apk_rec["archive"]["mobile_framework"]["name"])
        self.assertTrue(any("Mobile Framework: React Native (Hermes Bytecode HBC v96)" in l for l in apk_rec["tactical_leads"]))

        # 5. Dlang binary runtime & _Dmain candidate resolution
        # Build ELF64 with main wrapper at 0x1140 that does `lea rdx, [rip + 0x10]; call 0x1200`
        d_elf = bytearray(_build_minimal_elf64())
        # Overwrite .text at 0x140 (vaddr 0x1140):
        # 48 8d 15 10 00 00 00 (lea rdx, [rip + 0x10] -> 0x1147 + 0x10 = 0x1157); e8 00 00 00 00 (call); c3
        d_elf[0x140 : 0x14D] = b"\x48\x8d\x15\x10\x00\x00\x00\xe8\x00\x00\x00\x00\xc3"
        d_bin = bytes(d_elf) + b"\x00_Dmain\x00ldc-1.41.0\x00/dlang/\x00"
        d_path = self.root / "dior_test"
        d_path.write_bytes(d_bin)
        d_rec = run_recon(d_path)
        self.assertTrue(any("D (Dlang) Binary [LDC 1.41.0]" in r for r in d_rec["runtime_fingerprint"]))
        self.assertEqual(d_rec["dlang_main_candidate"], "0x1157")
        self.assertTrue(any("Dlang user main (_Dmain) candidate at 0x1157" in l for l in d_rec["tactical_leads"]))

        # 6. Go Concurrency detection
        go_chan_elf = bytes(_build_minimal_elf64()) + b"\x00Go build ID: go1.25.0\x00runtime.makechan\x00runtime.chansend\x00"
        go_chan_path = self.root / "go_chan_test"
        go_chan_path.write_bytes(go_chan_elf)
        go_chan_rec = run_recon(go_chan_path)
        self.assertTrue(go_chan_rec["go_concurrency"])
        self.assertTrue(any("Go Concurrency" in l for l in go_chan_rec["tactical_leads"]))

    def test_main_finder_and_cwe_audit(self) -> None:
        """Test multi-architecture main() resolver and defensive static CWE auditor."""
        from revtool.cwe_audit import audit_binary
        from revtool.main_finder import resolve_main
        from revtool.recon import run_recon

        # 1. Non-PIE stripped ELF x86_64: _start -> mov rdi, 0x1140; call __libc_start_main
        elf_data = bytearray(_build_minimal_elf64())
        # Overwrite _start at 0x140 with `mov rdi, 0x1140; call 0x114c; hlt`
        # 48 c7 c7 40 11 00 00 (mov rdi, 0x1140); e8 00 00 00 00 (call); f4 (hlt)
        elf_data[0x140 : 0x14D] = b"\x48\xc7\xc7\x40\x11\x00\x00\xe8\x00\x00\x00\x00\xf4"
        elf_path = self.root / "test_nonpie_stripped"
        elf_path.write_bytes(bytes(elf_data))

        rep = analyze_file(elf_path)
        # In stripped scenario (remove symbols)
        rep["symbols"] = []
        resolved = resolve_main(bytes(elf_data), rep)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["address_hex"], "0x1140")
        self.assertEqual(resolved["name"], "main")
        self.assertIn("ELF x86_64", resolved["origin"])

        # 2. CWE Audit: gets without Stack Canary -> CRITICAL CWE-120 / CWE-242
        rep_vuln = {
            "format": "ELF",
            "header": {"architecture": "x86_64", "bits": 64},
            "mitigations": {"Stack Canary": "Not Found", "NX": "Enabled", "PIE": "Disabled"},
            "imported_symbols": [{"name": "gets"}, {"name": "rand"}],
            "plt_map": {},
            "symbols": [],
            "sections": [],
        }
        audit_res = audit_binary(b"", rep_vuln)
        crit_finds = [f for f in audit_res["findings"] if f["severity"] == "CRITICAL"]
        self.assertTrue(len(crit_finds) >= 1)
        self.assertIn("CWE-120", crit_finds[0]["cwe"])
        self.assertIn("gets", crit_finds[0]["symbol"])

        # rand() -> CWE-338 (Weak PRNG)
        prng_finds = [f for f in audit_res["findings"] if "CWE-338" in f["cwe"]]
        self.assertTrue(len(prng_finds) >= 1)
        self.assertEqual(prng_finds[0]["severity"], "MEDIUM")

        # 3. CLI subcommand `audit` output and JSON mode
        out_buf = io.StringIO()
        with redirect_stdout(out_buf):
            rc = main(["audit", str(elf_path), "--no-banner"])
        self.assertEqual(rc, 0)
        self.assertIn("Vulnerability & CWE Static Audit", out_buf.getvalue())

        json_buf = io.StringIO()
        with redirect_stdout(json_buf):
            rc_json = main(["audit", str(elf_path), "--json"])
        self.assertEqual(rc_json, 0)
        parsed_json = json.loads(json_buf.getvalue())
        self.assertIn("findings", parsed_json)
        self.assertIn("summary", parsed_json)

    def test_cli_missing_file_returns_nonzero(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["triage", str(self.root / "nonexistent.bin")])
        self.assertEqual(rc, 1)
        self.assertIn("error", err.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
