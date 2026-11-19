"""Command-line interface for revtool."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from revtool import __version__
from revtool.crypto_scan import scan_crypto_constants, scan_embedded_magic
from revtool.disasm import disassemble_file
from revtool.explain import explain_recon, explain_subcommand
from revtool.display import (
    LOGO_LINES,
    Theme,
    format_blobs,
    format_crypto,
    format_disasm,
    format_imports,
    format_info,
    format_recon,
    format_recon_with_phase,
    format_sections,
    format_strings,
    format_symbols,
    format_triage,
    format_xform,
    render_banner,
    render_section_header,
    render_table,
)
from revtool.parsers import analyze_file
from revtool.recon import annotate_go_blob_xrefs, find_entropy_blobs, run_recon
from revtool.strings_scan import extract_strings
from revtool.xform import transform_slice


def _add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file", help="Path file target (ELF, PE, APK, ZIP, atau biner mentah)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Keluarkan output JSON rapi (cocok untuk script / jq)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Matikan warna ANSI di terminal",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Sembunyikan logo ASCII REVTOOLS",
    )
    parser.add_argument(
        "--no-explain",
        action="store_true",
        help="Sembunyikan catatan penjelasan singkat",
    )


def _format_segments(report: dict, theme: Theme) -> str:
    segments = report.get("segments", [])
    lines = [render_section_header(f"Program Headers / Segments ({len(segments)})", theme).lstrip("\n")]
    if not segments:
        lines.append(f"  {theme.dim('No program headers / segments found in this file.')}")
        return "\n".join(lines)

    rows = [
        [
            str(seg["index"]),
            str(seg["type"]),
            f"0x{seg['offset']:06x}",
            f"0x{seg['vaddr']:08x}",
            f"0x{seg['filesz']:x}",
            f"0x{seg['memsz']:x}",
            str(seg["perms"]),
            f"0x{seg['align']:x}",
        ]
        for seg in segments
    ]
    lines.extend(
        render_table(
            headers=["Idx", "Type", "Offset", "VAddr", "FileSz", "MemSz", "Perm", "Align"],
            rows=rows,
            theme=theme,
            alignments=["right", "left", "right", "right", "right", "right", "left", "right"],
        )
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    inner_width = 58
    box_lines = [
        "+" + "-" * inner_width + "+",
        *[f"| {line.ljust(inner_width - 2)} |" for line in LOGO_LINES],
        f"| {f'Static Binary Triage & RE Toolkit  v{__version__}'.ljust(inner_width - 2)} |",
        f"| {'Mode: Reverse Engineering | Engine: ELF/PE/Mach-O/APK'.ljust(inner_width - 2)} |",
        "+" + "-" * inner_width + "+",
    ]
    banner_text = "\n".join(box_lines)
    parser = argparse.ArgumentParser(
        prog="revtool",
        description=(
            f"{banner_text}\n\n"
            "Toolkit CLI analisis statis, recon, dan disassembly biner (ELF / PE / Mach-O / APK)."
        ),
        epilog=(
            "contoh penggunaan:\n"
            "  revtool recon ./challenge\n"
            "  revtool triage ./challenge\n"
            "  revtool sections ./challenge\n"
            "  revtool imports ./challenge -l 0\n"
            "  revtool strings ./challenge -i\n"
            "  revtool crypto ./challenge\n"
            "  revtool blobs ./challenge\n"
            "  revtool disasm ./challenge -a 0x11c0 -c 30\n"
            "  revtool xform ./challenge -o 0x2019 -n 0x100 --rol 8 --xor CYB\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        title="subcommand",
        dest="command",
        metavar="<command>",
    )

    # triage
    p_triage = subparsers.add_parser(
        "triage",
        help="Ringkasan struktur file, header, proteksi, section, dan import",
    )
    _add_common_flags(p_triage)

    # info
    p_info = subparsers.add_parser(
        "info",
        help="Tampilkan hash file, format magic, header biner, dan status proteksi",
    )
    _add_common_flags(p_info)

    # sections
    p_sections = subparsers.add_parser(
        "sections",
        help="Daftar section (.text, .rodata, .data) beserta alamat, ukuran, izin RWX, dan entropi",
    )
    _add_common_flags(p_sections)

    # segments
    p_segments = subparsers.add_parser(
        "segments",
        help="Daftar ELF program headers / segments (PT_LOAD, PT_INTERP, GNU_STACK, RELRO)",
    )
    _add_common_flags(p_segments)

    # imports
    p_imports = subparsers.add_parser(
        "imports",
        help="Daftar library eksternal dan fungsi yang di-import",
    )
    _add_common_flags(p_imports)
    p_imports.add_argument(
        "-f",
        "--filter",
        dest="name_filter",
        help="Filter nama library atau simbol (tidak peka huruf besar/kecil)",
    )
    p_imports.add_argument(
        "-l",
        "--limit",
        type=int,
        default=100,
        help="Maksimum jumlah baris (default: 100, isi 0 untuk semua)",
    )

    # symbols
    p_symbols = subparsers.add_parser(
        "symbols",
        help="Daftar tabel simbol internal (ELF .symtab/.dynsym atau PE exports)",
    )
    _add_common_flags(p_symbols)
    p_symbols.add_argument(
        "-f",
        "--filter",
        dest="name_filter",
        help="Filter nama simbol",
    )
    p_symbols.add_argument(
        "-t",
        "--type",
        dest="sym_type",
        help="Filter tipe simbol (mis. FUNC, OBJECT, NOTYPE)",
    )
    p_symbols.add_argument(
        "-l",
        "--limit",
        type=int,
        default=100,
        help="Maksimum simbol yang ditampilkan (default: 100, isi 0 untuk semua)",
    )

    # disasm
    p_disasm = subparsers.add_parser(
        "disasm",
        help="Disassembly instruksi assembly di Entry Point, section, atau alamat tertentu",
    )
    _add_common_flags(p_disasm)
    p_disasm.add_argument(
        "-s",
        "--section",
        dest="section_name",
        help="Disasm mulai dari awal section tertentu (mis. .text)",
    )
    p_disasm.add_argument(
        "-a",
        "--addr",
        dest="address",
        help="Virtual address awal disasm (hex seperti 0x11c0 atau desimal)",
    )
    p_disasm.add_argument(
        "-c",
        "--count",
        type=int,
        default=30,
        help="Jumlah instruksi maksimum yang ditampilkan (default: 30)",
    )
    p_disasm.add_argument(
        "--raw",
        "--asm-only",
        dest="raw_asm",
        action="store_true",
        help="Keluarkan hanya baris assembly bersih (tanpa header/tabel/penjelasan) untuk pipe ke tool lain",
    )

    # recon
    p_recon = subparsers.add_parser(
        "recon",
        help="Recon lengkap CTF RE (bahasa/packer, main() stripped, API mencurigakan, trap, kripto, APK)",
    )
    _add_common_flags(p_recon)

    # strings
    p_strings = subparsers.add_parser(
        "strings",
        help="Ekstrak string ASCII/UTF-16 beserta offset, VAddr, section, dan tag recon",
    )
    _add_common_flags(p_strings)
    p_strings.add_argument("-m", "--min-len", type=int, default=5, help="Panjang minimum string (default: 5)")
    p_strings.add_argument(
        "-e",
        "--encoding",
        choices=("ascii", "utf16", "both"),
        default="both",
        help="Encoding string yang dipindai (default: both)",
    )
    p_strings.add_argument("-r", "--regex", dest="regex_filter", help="Filter regex (case-insensitive)")
    p_strings.add_argument("-t", "--tag", dest="tag_filter", help="Filter tag (FLAG_FMT, URL, BASE64_CAND, CRYPTO, ANTI_DBG, PATH)")
    p_strings.add_argument("-s", "--section", dest="section_filter", help="Filter berdasarkan nama section")
    p_strings.add_argument("-i", "--interesting", action="store_true", help="Hanya tampilkan string yang memiliki tag menarik")
    p_strings.add_argument("-l", "--limit", type=int, default=100, help="Maksimum string yang ditampilkan (default: 100, isi 0 untuk semua)")

    # crypto
    p_crypto = subparsers.add_parser(
        "crypto",
        help="Pindai konstanta kripto standar (AES, SHA, MD5, CRC32, TEA, ChaCha20, Base64) & Zlib",
    )
    _add_common_flags(p_crypto)

    # blobs
    p_blobs = subparsers.add_parser(
        "blobs",
        help="Cari area byte berentropi tinggi (data terenkripsi/shellcode) & file tertanam",
    )
    _add_common_flags(p_blobs)
    p_blobs.add_argument("-w", "--window", type=int, default=128, help="Ukuran jendela scan dalam byte (default: 128)")
    p_blobs.add_argument("-t", "--threshold", type=float, default=6.8, help="Ambang batas entropi 0..8 (default: 6.8)")
    p_blobs.add_argument("--min-size", type=int, default=128, help="Ukuran minimum blob dalam byte (default: 128)")

    # xform
    p_xform = subparsers.add_parser(
        "xform",
        help="Potong & uji transformasi byte (ROL/ROR, XOR, swap endian, unhex, base64)",
    )
    _add_common_flags(p_xform)
    p_xform.add_argument("-s", "--section", dest="section_name", help="Ambil potongan dari nama section tertentu")
    p_xform.add_argument("-o", "--offset", default="0", help="Offset awal file/section (hex mis. 0x2019 atau desimal)")
    p_xform.add_argument("-n", "--length", help="Panjang byte yang dipotong (hex/desimal); kosongkan untuk sampai akhir")
    p_xform.add_argument("--swap", action="store_true", help="Tukar urutan byte (endianness) per --word-size")
    p_xform.add_argument("--rol", type=int, dest="rol_bits", help="Putar bit ke kiri (ROL) sebanyak N bit per word")
    p_xform.add_argument("--ror", type=int, dest="ror_bits", help="Putar bit ke kanan (ROR) sebanyak N bit per word")
    p_xform.add_argument("--word-size", type=int, default=4, choices=(1, 2, 4, 8), help="Ukuran word dalam byte untuk rol/ror/swap (default: 4)")
    p_xform.add_argument("--xor", dest="xor_key", help="Kunci XOR (teks biasa, 0x..., atau hex:...)")
    p_xform.add_argument("--unhex", action="store_true", help="Decode teks hex menjadi byte mentah")
    p_xform.add_argument("--b64d", action="store_true", help="Decode Base64")
    p_xform.add_argument("--out", dest="out_file", help="Simpan hasil byte ke file output")

    return parser


def _parse_int_addr(raw: str | None) -> int | None:
    if raw is None:
        return None
    return int(raw, 0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "recon":
        try:
            recon_report = run_recon(args.file)
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as exc:
            print(f"revtool: error: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(recon_report, indent=2))
            return 0
        theme = Theme(use_color=not args.no_color)
        if not getattr(args, "no_banner", False):
            print(render_banner(__version__, theme))
            print()
        recon_text, next_phase = format_recon_with_phase(recon_report, theme)
        print(recon_text)
        if not getattr(args, "no_explain", False):
            print(explain_recon(recon_report, theme, phase=next_phase))
        return 0

    if args.command == "xform":
        try:
            res = transform_slice(
                args.file,
                section_name=args.section_name,
                offset=int(args.offset, 0),
                length=_parse_int_addr(args.length),
                rol_bits=args.rol_bits,
                ror_bits=args.ror_bits,
                word_size=args.word_size,
                xor_key=args.xor_key,
                swap_endian=args.swap,
                from_hex=args.unhex,
                from_b64=args.b64d,
                out_file=args.out_file,
            )
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError, ValueError) as exc:
            print(f"revtool: error: {exc}", file=sys.stderr)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(res, indent=2))
            return 0
        theme = Theme(use_color=not args.no_color)
        print(format_xform(res, theme))
        if not getattr(args, "no_explain", False):
            no_ops = (
                args.section_name is None
                and int(args.offset, 0) == 0
                and args.length is None
                and args.rol_bits is None
                and args.ror_bits is None
                and args.xor_key is None
                and not args.swap
                and not args.unhex
                and not args.b64d
            )
            print(explain_subcommand("xform", {"no_ops": no_ops}, theme))
        return 0

    if args.command == "disasm":
        try:
            addr_val = _parse_int_addr(args.address)
            dis_report = disassemble_file(
                args.file,
                section_name=args.section_name,
                address=addr_val,
                count=max(1, args.count),
            )
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError, ValueError, RuntimeError) as exc:
            print(f"revtool: error: {exc}", file=sys.stderr)
            return 1

        if getattr(args, "json", False):
            print(json.dumps(dis_report, indent=2))
            return 0

        if getattr(args, "raw_asm", False):
            for ins in dis_report.get("instructions", []):
                op = f" {ins['op_str']}" if ins["op_str"] else ""
                print(f"{ins['address']}: {ins['mnemonic']}{op}")
            return 0

        theme = Theme(use_color=not args.no_color)
        print(format_disasm(dis_report, theme))
        if not getattr(args, "no_explain", False):
            print(explain_subcommand("disasm", {}, theme))
        return 0

    try:
        report = analyze_file(args.file)
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as exc:
        print(f"revtool: error: {exc}", file=sys.stderr)
        return 1

    if args.command in ("strings", "crypto", "blobs"):
        data = Path(args.file).read_bytes()
        fmt = report.get("format", "UNKNOWN")
        image_base = int(report.get("header", {}).get("image_base", 0) or 0)
        sections = report.get("sections", [])
        theme = Theme(use_color=not getattr(args, "no_color", False))

        if args.command == "strings":
            strs = extract_strings(
                data,
                sections=sections,
                image_base=image_base,
                fmt=fmt,
                min_len=max(1, args.min_len),
                encoding=args.encoding,
                regex_filter=args.regex_filter,
                tag_filter=args.tag_filter,
                section_filter=args.section_filter,
                only_interesting=args.interesting,
            )
            if getattr(args, "json", False):
                print(json.dumps({"file": report["file"]["path"], "strings": strs}, indent=2))
                return 0
            limit = None if args.limit <= 0 else args.limit
            print(format_strings(strs, theme, limit=limit))
            if not getattr(args, "no_explain", False):
                print(explain_subcommand("strings", {}, theme))
            return 0

        if args.command == "crypto":
            crypto_hits = scan_crypto_constants(data, sections, image_base, fmt)
            magic_hits = scan_embedded_magic(data, sections, image_base, fmt)
            if getattr(args, "json", False):
                print(json.dumps({"file": report["file"]["path"], "crypto": crypto_hits, "embedded_magic": magic_hits}, indent=2))
                return 0
            print(format_crypto(crypto_hits, magic_hits, theme))
            if not getattr(args, "no_explain", False):
                print(explain_subcommand("crypto", {}, theme))
            return 0

        if args.command == "blobs":
            crypto_hits = scan_crypto_constants(data, sections, image_base, fmt)
            crypto_ranges = [
                (int(c["offset"]), int(c["offset"]) + int(c.get("size", 16)))
                for c in crypto_hits
            ]
            blobs = find_entropy_blobs(
                data,
                sections=sections,
                image_base=image_base,
                fmt=fmt,
                window=max(32, args.window),
                threshold=args.threshold,
                min_blob_size=max(32, args.min_size),
                exclude_ranges=crypto_ranges,
            )
            if any(s.get("table") == ".gopclntab" for s in report.get("symbols", [])):
                blobs = annotate_go_blob_xrefs(data, report, blobs)
            magic_hits = scan_embedded_magic(data, sections, image_base, fmt)
            if getattr(args, "json", False):
                print(json.dumps({"file": report["file"]["path"], "blobs": blobs, "embedded_magic": magic_hits}, indent=2))
                return 0
            print(format_blobs(blobs, magic_hits, theme))
            if not getattr(args, "no_explain", False):
                print(explain_subcommand("blobs", {}, theme))
            return 0

    if getattr(args, "json", False):
        if args.command == "info":
            payload = {
                "file": report["file"],
                "format": report["format"],
                "header": report["header"],
                "mitigations": report["mitigations"],
                "hints": report["hints"],
                "warnings": report["warnings"],
            }
        elif args.command == "sections":
            payload = {
                "file": report["file"]["path"],
                "format": report["format"],
                "sections": report["sections"],
                "hints": report["hints"],
            }
        elif args.command == "segments":
            payload = {
                "file": report["file"]["path"],
                "format": report["format"],
                "segments": report["segments"],
            }
        elif args.command == "imports":
            filt = args.name_filter.lower() if args.name_filter else None
            imp_syms = report["imported_symbols"]
            if filt:
                imp_syms = [s for s in imp_syms if filt in s["name"].lower()]
            payload = {
                "file": report["file"]["path"],
                "format": report["format"],
                "needed_libraries": report["needed_libraries"],
                "imports": report["imports"],
                "imported_symbols": imp_syms,
            }
        elif args.command == "symbols":
            syms = report["symbols"]
            if args.name_filter:
                nf = args.name_filter.lower()
                syms = [s for s in syms if nf in s["name"].lower()]
            if args.sym_type:
                st = args.sym_type.upper()
                syms = [s for s in syms if s.get("type", "").upper() == st]
            payload = {
                "file": report["file"]["path"],
                "format": report["format"],
                "symbols": syms,
            }
        else:
            payload = report

        print(json.dumps(payload, indent=2))
        return 0

    theme = Theme(use_color=not args.no_color)

    if args.command == "triage":
        if not getattr(args, "no_banner", False):
            print(render_banner(__version__, theme))
            print()
        print(format_triage(report, theme))
    elif args.command == "info":
        print(format_info(report, theme))
    elif args.command == "sections":
        print(format_sections(report, theme))
    elif args.command == "segments":
        print(_format_segments(report, theme))
    elif args.command == "imports":
        limit = None if args.limit <= 0 else args.limit
        print(format_imports(report, theme, name_filter=args.name_filter, limit=limit))
    elif args.command == "symbols":
        limit = None if args.limit <= 0 else args.limit
        print(
            format_symbols(
                report,
                theme,
                name_filter=args.name_filter,
                sym_type=args.sym_type,
                limit=limit,
            )
        )

    if not getattr(args, "no_explain", False):
        print(explain_subcommand(args.command, {}, theme))

    return 0


if __name__ == "__main__":
    sys.exit(main())
