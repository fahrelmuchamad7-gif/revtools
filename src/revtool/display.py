"""Terminal formatting and ANSI color rendering for revtool."""

from __future__ import annotations

import os
import sys
from typing import Any


class Theme:
    """Minimal ANSI color helper respecting TTY and NO_COLOR."""

    def __init__(self, use_color: bool = True) -> None:
        env_no_color = os.environ.get("NO_COLOR") is not None
        is_tty = sys.stdout.isatty()
        self.enabled = use_color and not env_no_color and is_tty

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def bold_cyan(self, text: str) -> str:
        return self._wrap("1;36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def magenta(self, text: str) -> str:
        return self._wrap("35", text)

    def blue(self, text: str) -> str:
        return self._wrap("34", text)

    def badge_info(self) -> str:
        return self.bold_cyan("[*]")

    def badge_ok(self) -> str:
        return self.green("[+]")

    def badge_warn(self) -> str:
        return self.yellow("[!]")

    def badge_err(self) -> str:
        return self.red("[-]")

    def badge_step(self) -> str:
        return self.magenta("[>]")


def _strip_ansi_len(text: str) -> int:
    """Compute display width ignoring ANSI escape sequences."""
    length = 0
    in_escape = False
    for ch in text:
        if in_escape:
            if ch == "m":
                in_escape = False
        elif ch == "\033":
            in_escape = True
        else:
            length += 1
    return length


def _pad(text: str, width: int, align: str = "left") -> str:
    pad_len = max(0, width - _strip_ansi_len(text))
    if align == "right":
        return (" " * pad_len) + text
    return text + (" " * pad_len)


def render_section_header(title: str, theme: Theme) -> str:
    bar = theme.dim("-" * max(24, min(64, len(title) + 8)))
    return f"\n{theme.badge_ok()} {theme.bold_cyan(title)}\n  {bar}"


def render_phase_header(phase: int, title: str, theme: Theme) -> str:
    bar = theme.dim("=" * 60)
    return f"\n{theme.badge_info()} {theme.bold_cyan(f'[Phase {phase}] {title}')}\n{bar}"


def render_kv_block(items: list[tuple[str, str]], theme: Theme, indent: int = 2) -> list[str]:
    if not items:
        return []
    key_width = max(len(k) for k, _ in items)
    prefix = " " * indent
    lines: list[str] = []
    for key, val in items:
        lines.append(f"{prefix}{theme.cyan(key.ljust(key_width))} : {val}")
    return lines


def render_table(
    headers: list[str],
    rows: list[list[str]],
    theme: Theme,
    alignments: list[str] | None = None,
    indent: int = 2,
) -> list[str]:
    if not rows:
        return [f"{' ' * indent}{theme.dim('(none)')}"]
    aligns = alignments or ["left"] * len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], _strip_ansi_len(cell))

    prefix = " " * indent
    header_line = prefix + "  ".join(
        theme.bold(_pad(h, widths[i], aligns[i])) for i, h in enumerate(headers)
    )
    sep_line = prefix + "  ".join(theme.dim("-" * widths[i]) for i in range(len(headers)))
    lines = [header_line, sep_line]
    for row in rows:
        line = prefix + "  ".join(
            _pad(row[i], widths[i], aligns[i]) for i in range(len(headers))
        )
        lines.append(line)
    return lines


def _color_perms(perms: str, theme: Theme) -> str:
    if "W" in perms and "X" in perms:
        return theme.red(perms)
    if "X" in perms:
        return theme.yellow(perms)
    if "W" in perms:
        return theme.magenta(perms)
    return theme.green(perms)


def _color_entropy(entropy: float, theme: Theme) -> str:
    text = f"{entropy:.2f}"
    if entropy >= 7.2:
        return theme.red(text)
    if entropy >= 6.5:
        return theme.yellow(text)
    return theme.green(text)


def _color_mitigation(value: str, theme: Theme) -> str:
    lower = value.lower()
    if any(tok in lower for tok in ("enabled", "full relro", "found", "yes (")):
        if "not found" in lower or "disabled" in lower:
            return theme.yellow(value)
        return theme.green(value)
    if any(tok in lower for tok in ("disabled", "no relro", "executable stack", "not found")):
        return theme.red(value)
    if any(tok in lower for tok in ("partial", "shared object")):
        return theme.yellow(value)
    return value


def format_info(report: dict[str, Any], theme: Theme) -> str:
    """Render detailed file & binary header info."""
    lines: list[str] = []
    f = report["file"]
    hdr = report.get("header", {})

    lines.append(render_section_header("File Overview", theme).lstrip("\n"))
    lines.extend(
        render_kv_block(
            [
                ("File", f["path"]),
                ("Size", f["size_human"]),
                ("Format", f"{f['format']} — {f['magic_description']}"),
                ("Entropy", f"{_color_entropy(f['entropy'], theme)} / 8.00"),
                ("MD5", f["hashes"]["md5"]),
                ("SHA-1", f["hashes"]["sha1"]),
                ("SHA-256", f["hashes"]["sha256"]),
            ],
            theme,
        )
    )

    if hdr:
        lines.append(render_section_header(f"{report['format']} Header", theme))
        hdr_items: list[tuple[str, str]] = [
            ("Class", f"{hdr.get('class', '-')} ({hdr.get('bits', '?')}-bit, {hdr.get('endianness', '-')})"),
            ("Architecture", str(hdr.get("architecture", "-"))),
            ("Type", str(hdr.get("type", "-"))),
        ]
        if hdr.get("os_abi"):
            hdr_items.append(("OS/ABI", str(hdr["os_abi"])))
        if hdr.get("subsystem"):
            hdr_items.append(("Subsystem", str(hdr["subsystem"])))
        if "image_base" in hdr:
            hdr_items.append(("Image Base", f"0x{hdr['image_base']:x}"))
        if "entry_point" in hdr:
            ep = f"0x{hdr['entry_point']:x}"
            if "entry_point_rva" in hdr:
                ep += f" (RVA: 0x{hdr['entry_point_rva']:x})"
            hdr_items.append(("Entry Point", ep))
        if hdr.get("interpreter"):
            hdr_items.append(("Interpreter", str(hdr["interpreter"])))
        if hdr.get("timestamp"):
            hdr_items.append(("Timestamp", str(hdr["timestamp"])))
        if "program_headers" in hdr:
            hdr_items.append(("Segments", str(hdr["program_headers"])))
        if "section_headers" in hdr:
            hdr_items.append(("Sections", str(hdr["section_headers"])))
        lines.extend(render_kv_block(hdr_items, theme))

    mitigations = report.get("mitigations", {})
    if mitigations:
        lines.append(render_section_header("Binary Metadata & Flags", theme))
        mit_items = [(k, _color_mitigation(v, theme)) for k, v in mitigations.items()]
        lines.extend(render_kv_block(mit_items, theme))

    hints = report.get("hints", [])
    if hints:
        lines.append(render_section_header("Static Hints", theme))
        for h in hints:
            lines.append(f"  {theme.yellow('[!]')} {h}")

    warnings = report.get("warnings", [])
    if warnings:
        lines.append(render_section_header("Warnings", theme))
        for w in warnings:
            lines.append(f"  {theme.red('[WARN]')} {w}")

    return "\n".join(lines)


def format_sections(report: dict[str, Any], theme: Theme) -> str:
    """Render binary sections table."""
    lines: list[str] = []
    sections = report.get("sections", [])
    lines.append(render_section_header(f"Sections ({len(sections)})", theme).lstrip("\n"))
    if not sections:
        lines.append(f"  {theme.dim('No section headers found in this file.')}")
        return "\n".join(lines)

    rows: list[list[str]] = []
    for sec in sections:
        rows.append(
            [
                str(sec["index"]),
                sec["name"] or "<unnamed>",
                str(sec.get("type", "-")),
                f"0x{sec['addr']:08x}",
                f"0x{sec['offset']:06x}",
                f"0x{sec['size']:x} ({sec['size']})",
                _color_perms(sec["perms"], theme),
                _color_entropy(sec["entropy"], theme),
            ]
        )

    lines.extend(
        render_table(
            headers=["Idx", "Name", "Type", "VAddr", "Offset", "Size", "Perm", "Entropy"],
            rows=rows,
            theme=theme,
            alignments=["right", "left", "left", "right", "right", "right", "left", "right"],
        )
    )

    hints = report.get("hints", [])
    if hints:
        lines.append(render_section_header("Section Notes", theme))
        for h in hints:
            lines.append(f"  {theme.yellow('[!]')} {h}")

    return "\n".join(lines)


def format_imports(
    report: dict[str, Any],
    theme: Theme,
    name_filter: str | None = None,
    limit: int | None = None,
) -> str:
    """Render linked libraries and imported symbols."""
    lines: list[str] = []
    fmt = report.get("format", "UNKNOWN")
    needed = report.get("needed_libraries", [])
    filt = name_filter.lower() if name_filter else None

    if fmt == "PE":
        imports = report.get("imports", [])
        lines.append(render_section_header(f"Imported DLLs ({len(imports)})", theme).lstrip("\n"))
        if not imports:
            lines.append(f"  {theme.dim('No PE import table entries found.')}")
            return "\n".join(lines)
        shown = 0
        for imp in imports:
            funcs = imp.get("functions", [])
            if filt:
                if filt not in imp["library"].lower():
                    funcs = [fn for fn in funcs if filt in fn.lower()]
                if not funcs and filt not in imp["library"].lower():
                    continue
            lines.append(f"  {theme.bold_cyan(imp['library'])} ({len(funcs)} functions)")
            for fn in funcs:
                if limit is not None and shown >= limit:
                    lines.append(f"    {theme.dim(f'... truncated at --limit {limit}')}")
                    return "\n".join(lines)
                lines.append(f"    - {fn}")
                shown += 1
        return "\n".join(lines)

    # ELF / generic layout
    lines.append(render_section_header(f"Needed Shared Libraries ({len(needed)})", theme).lstrip("\n"))
    if needed:
        for lib in needed:
            lines.append(f"  - {theme.bold_cyan(lib)}")
    else:
        lines.append(f"  {theme.dim('None (statically linked or no DT_NEEDED entries)')}")

    imp_syms = report.get("imported_symbols", [])
    if filt:
        imp_syms = [s for s in imp_syms if filt in s["name"].lower()]

    total = len(imp_syms)
    if limit is not None:
        imp_syms = imp_syms[:limit]

    lines.append(render_section_header(f"Imported Dynamic Symbols ({total})", theme))
    rows = [
        [s["name"], s["type"], s["bind"], s["table"]]
        for s in imp_syms
    ]
    lines.extend(render_table(["Symbol", "Type", "Bind", "Table"], rows, theme))
    if limit is not None and total > limit:
        lines.append(f"  {theme.dim(f'... showing {limit} of {total} imported symbols (use --limit 0 for all)')}")

    return "\n".join(lines)


def format_symbols(
    report: dict[str, Any],
    theme: Theme,
    name_filter: str | None = None,
    sym_type: str | None = None,
    limit: int | None = None,
) -> str:
    """Render symbol table (ELF .symtab/.dynsym or PE exports)."""
    syms = report.get("symbols", [])
    if name_filter:
        nf = name_filter.lower()
        syms = [s for s in syms if nf in s["name"].lower()]
    if sym_type:
        st = sym_type.upper()
        syms = [s for s in syms if s.get("type", "").upper() == st]

    total = len(syms)
    if limit is not None:
        syms = syms[:limit]

    title = "Exported Symbols" if report.get("format") == "PE" else "Symbols"
    lines = [render_section_header(f"{title} ({total})", theme).lstrip("\n")]
    rows = [
        [
            f"0x{s['value']:08x}",
            str(s.get("size", 0)),
            s.get("type", "-"),
            s.get("bind", "-"),
            s.get("section", "-"),
            s.get("table", "-"),
            s["name"],
        ]
        for s in syms
    ]
    lines.extend(
        render_table(
            headers=["Address", "Size", "Type", "Bind", "Section", "Table", "Name"],
            rows=rows,
            theme=theme,
            alignments=["right", "right", "left", "left", "left", "left", "left"],
        )
    )
    if limit is not None and total > limit:
        lines.append(f"  {theme.dim(f'... showing {limit} of {total} symbols (use --limit 0 for all)')}")
    return "\n".join(lines)


def format_triage(report: dict[str, Any], theme: Theme) -> str:
    """Render compact one-shot triage dashboard combining overview, sections, and imports."""
    parts = [format_info(report, theme)]

    sections = report.get("sections", [])
    if sections:
        parts.append("\n" + format_sections(report, theme))

    needed = report.get("needed_libraries", [])
    imp_syms = report.get("imported_symbols", [])
    exports = report.get("exports", [])

    summary_lines: list[str] = []
    if needed or imp_syms or exports:
        summary_lines.append(render_section_header("Imports & Symbols Summary", theme))
        items: list[tuple[str, str]] = [
            ("Linked Libraries", ", ".join(needed[:8]) + (" ..." if len(needed) > 8 else "") if needed else "None"),
            ("Imported Symbols", str(len(imp_syms))),
            ("Total Symbols", str(len(report.get("symbols", [])))),
            ("Exported Symbols", str(len(exports))),
        ]
        summary_lines.extend(render_kv_block(items, theme))
        if imp_syms:
            preview = ", ".join(s["name"] for s in imp_syms[:12])
            if len(imp_syms) > 12:
                preview += f", ... (+{len(imp_syms) - 12} more)"
            summary_lines.append(f"  {theme.dim('Sample imports:')} {preview}")
        parts.append("\n".join(summary_lines))

    return "\n".join(parts)


LOGO_LINES: list[str] = [
    r"  ____  _______     _______ ___   ___  _     ____  ",
    r" |  _ \| ____\ \   / /_   _/ _ \ / _ \| |   / ___| ",
    r" | |_) |  _|  \ \ / /  | || | | | | | | |   \___ \ ",
    r" |  _ <| |___  \ V /   | || |_| | |_| | |___ ___) |",
    r" |_| \_\_____|  \_/    |_| \___/ \___/|_____|____/ ",
]


def render_banner(version: str, theme: Theme) -> str:
    """Render the REVTOOLS ASCII CLI logo inside a PwnPasi-style framework box."""
    inner_width = 58
    top = theme.cyan("+" + "-" * inner_width + "+")
    bot = theme.cyan("+" + "-" * inner_width + "+")
    lines = [top]
    for line in LOGO_LINES:
        padded = line.ljust(inner_width - 2)
        lines.append(f"{theme.cyan('|')} {theme.bold_cyan(padded)} {theme.cyan('|')}")
    tag = f"Static Binary Triage & RE Toolkit  v{version}".ljust(inner_width - 2)
    eng = "Mode: Reverse Engineering | Engine: ELF/PE/Mach-O/APK".ljust(inner_width - 2)
    lines.append(f"{theme.cyan('|')} {theme.bold(tag)} {theme.cyan('|')}")
    lines.append(f"{theme.cyan('|')} {theme.dim(eng)} {theme.cyan('|')}")
    lines.append(bot)
    return "\n".join(lines)


def format_cwe_audit(audit: dict[str, Any], theme: Theme) -> str:
    """Format static binary vulnerability audit and CWE mapping."""
    lines: list[str] = []
    findings = audit.get("findings", [])
    summary = audit.get("summary", {})

    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    info = summary.get("info", 0)

    header_title = f"Vulnerability & CWE Static Audit (Findings: {len(findings)})"
    lines.append(render_section_header(header_title, theme).lstrip("\n"))

    summary_parts = []
    if crit > 0:
        summary_parts.append(theme.red(f"{crit} CRITICAL"))
    if high > 0:
        summary_parts.append(theme.red(f"{high} HIGH"))
    if med > 0:
        summary_parts.append(theme.yellow(f"{med} MEDIUM"))
    if info > 0:
        summary_parts.append(theme.cyan(f"{info} INFO"))

    if not summary_parts:
        summary_parts.append(theme.green("0 Findings (Clean)"))

    lines.append(f"  {theme.badge_info()} {theme.bold('Audit Summary:')} {', '.join(summary_parts)}")

    mits = audit.get("mitigations", {})
    if mits:
        canary = mits.get("Stack Canary", "-")
        nx = mits.get("NX", "-")
        pie = mits.get("PIE", "-")
        relro = mits.get("RELRO", "-")
        lines.append(
            f"  {theme.badge_info()} {theme.bold('Hardening:')} "
            f"Canary: {_color_mitigation(canary, theme)} | "
            f"NX: {_color_mitigation(nx, theme)} | "
            f"PIE: {_color_mitigation(pie, theme)} | "
            f"RELRO: {_color_mitigation(relro, theme)}"
        )
    lines.append("")

    if not findings:
        lines.append(f"  {theme.badge_ok()} {theme.dim('Tidak ditemukan API terlarang atau kerentanan statis berisiko tinggi.')}")
        return "\n".join(lines)

    for idx, f in enumerate(findings, 1):
        sev = f["severity"]
        if sev == "CRITICAL":
            sev_badge = theme.red(f"[{sev}]")
        elif sev == "HIGH":
            sev_badge = theme.red(f"[{sev}]")
        elif sev == "MEDIUM":
            sev_badge = theme.yellow(f"[{sev}]")
        else:
            sev_badge = theme.cyan(f"[{sev}]")

        cwe = f.get("cwe", "-")
        sym = f.get("symbol", "-")
        title = f.get("title", "-")
        desc = f.get("description", "-")
        re_note = f.get("re_note", "-")
        remediation = f.get("remediation", "-")

        lines.append(f"  {sev_badge} {theme.bold(cwe)}: {theme.bold_cyan(sym)} — {theme.bold(title)}")
        lines.append(f"      {theme.dim('Deskripsi')}  : {desc}")
        lines.append(f"      {theme.yellow('RE / CTF')}   : {re_note}")
        lines.append(f"      {theme.green('Remediasi')}  : {remediation}")
        if idx < len(findings):
            lines.append("")

    return "\n".join(lines)


def format_disasm(disasm_report: dict[str, Any], theme: Theme) -> str:
    """Render disassembled instructions table."""
    lines = [
        render_section_header(
            f"Disassembly ({disasm_report['architecture']} @ {disasm_report['start_address']})",
            theme,
        ).lstrip("\n")
    ]
    lines.extend(
        render_kv_block(
            [
                ("File", disasm_report["file"]),
                ("Format", disasm_report["format"]),
                ("Start VAddr", disasm_report["start_address"]),
                ("File Offset", disasm_report["file_offset"]),
            ],
            theme,
        )
    )
    insns = disasm_report.get("instructions", [])
    rows = [
        [
            theme.cyan(ins["address"]),
            theme.dim(ins["bytes"]),
            theme.yellow(ins["mnemonic"]),
            ins["op_str"],
        ]
        for ins in insns
    ]
    lines.append("")
    lines.extend(render_table(["Address", "Bytes", "Mnemonic", "Operands"], rows, theme))
    return "\n".join(lines)


def format_recon_with_phase(recon: dict[str, Any], theme: Theme) -> tuple[str, int]:
    """Render deep national-CTF reverse engineering reconnaissance report with sequential phases."""
    lines: list[str] = []
    f = recon["file"]
    hdr = recon.get("header", {})
    runtime = recon.get("runtime_fingerprint", [])
    phase = 1

    # Phase 1: Target & Checksec
    lines.append(render_phase_header(phase, "Target Profile & Checksec", theme).lstrip("\n"))
    phase += 1
    profile_items: list[tuple[str, str]] = [
        ("File", f["path"]),
        ("Size", f["size_human"]),
        ("Format", f"{f['format']} — {f['magic_description']}"),
        ("Overall Entropy", f"{_color_entropy(f['entropy'], theme)} / 8.00"),
    ]
    if hdr:
        profile_items.append(
            ("Arch / Class", f"{hdr.get('architecture', '-')} | {hdr.get('class', '-')} ({hdr.get('type', '-')})")
        )
        if hdr.get("fat_architectures"):
            profile_items.append(("Universal Slices", ", ".join(hdr["fat_architectures"])))
        if "entry_point" in hdr:
            profile_items.append(("Entry Point", f"0x{hdr['entry_point']:x}"))
    if runtime:
        profile_items.append(("Runtime / Compiler", ", ".join(runtime)))
    if recon.get("main_function"):
        mf = recon["main_function"]
        profile_items.append(
            ("Main Function", theme.bold_cyan(f"{mf['address_hex']} ({mf['name']}) via {mf['origin']}"))
        )
    elif recon.get("dlang_main_candidate"):
        profile_items.append(
            ("Dlang user main()", theme.bold_cyan(f"{recon['dlang_main_candidate']} (_Dmain)"))
        )
    elif recon.get("go_main_candidate"):
        profile_items.append(
            ("Go user main()", theme.bold_cyan(f"{recon['go_main_candidate']} (main.main)"))
        )
    elif recon.get("code_scan", {}).get("main_candidate"):
        profile_items.append(
            ("Stripped main()?", theme.bold_cyan(recon["code_scan"]["main_candidate"]))
        )
    arch_recon = recon.get("archive")
    if arch_recon and arch_recon.get("mobile_framework"):
        profile_items.append(("Mobile Framework", theme.bold_cyan(arch_recon["mobile_framework"]["name"])))
    pre_hooks = recon.get("pre_entry_hooks", {})
    if pre_hooks.get("tls_callbacks"):
        profile_items.append(
            ("TLS Callbacks", theme.red(", ".join(pre_hooks["tls_callbacks"][:6])))
        )
    if len(pre_hooks.get("init_array", [])) >= 2:
        profile_items.append(
            (".init_array", theme.yellow(", ".join(pre_hooks["init_array"][:6])))
        )
    lines.extend(render_kv_block(profile_items, theme))

    mits = recon.get("mitigations", {})
    if mits:
        lines.append("")
        lines.append(f"  {theme.badge_info()} {theme.bold('Checksec / Hardening:')}")
        lines.extend(render_kv_block([(k, _color_mitigation(v, theme)) for k, v in mits.items()], theme, indent=4))

    # Phase 2: Tactical Recon Leads
    leads = recon.get("tactical_leads", [])
    lines.append(render_phase_header(phase, f"Tactical Recon Leads ({len(leads)})", theme))
    phase += 1
    if leads:
        for lead in leads:
            lines.append(f"  {theme.badge_warn()} {lead}")
    else:
        lines.append(f"  {theme.badge_ok()} {theme.dim('Tidak ada anomali mencurigakan yang menonjol.')}")

    # Vulnerability & CWE Static Audit (if detected)
    cwe_audit = recon.get("cwe_audit", {})
    audit_findings = cwe_audit.get("findings", [])
    if audit_findings:
        lines.append("")
        lines.append(f"  {theme.badge_warn()} {theme.bold(f'Vulnerability & CWE Audit Findings ({len(audit_findings)}):')}")
        rows = []
        for f in audit_findings:
            sev = f["severity"]
            sev_col = (
                theme.red(sev) if sev in ("CRITICAL", "HIGH")
                else (theme.yellow(sev) if sev == "MEDIUM" else theme.cyan(sev))
            )
            rows.append([
                sev_col,
                theme.bold(f["cwe"]),
                theme.bold_cyan(f["symbol"]),
                f["title"],
            ])
        lines.extend(render_table(["Sev", "CWE", "Symbol / Surface", "Vulnerability Note"], rows, theme))

    # Phase 3 (only if present): API Behavior, main() Flow & Code Scan
    behaviors = recon.get("api_behaviors", [])
    anomalies = recon.get("code_scan", {}).get("anomalies", [])
    indirect_jumps = recon.get("code_scan", {}).get("indirect_jumps", [])
    main_flow = recon.get("main_flow")
    if behaviors or anomalies or indirect_jumps or (main_flow and (main_flow.get("calls") or main_flow.get("data_refs") or main_flow.get("inline_hints"))):
        lines.append(render_phase_header(phase, "Execution Flow, APIs & Code Anomalies", theme))
        phase += 1
    if main_flow and (main_flow.get("calls") or main_flow.get("data_refs") or main_flow.get("inline_hints")):
        mf_addr = main_flow["address"]
        lines.append(f"  {theme.badge_info()} {theme.bold(f'main() Static Trace ({mf_addr}):')}")
        mf_items: list[tuple[str, str]] = []
        if main_flow.get("inline_hints"):
            mf_items.append(("Inline Logic", "; ".join(main_flow["inline_hints"])))
        if main_flow.get("calls"):
            mf_items.append(("Calls / Targets", ", ".join(main_flow["calls"])))
        if main_flow.get("data_refs"):
            mf_items.append(("Data / String Refs", " | ".join(main_flow["data_refs"][:6])))
        lines.extend(render_kv_block(mf_items, theme, indent=4))
        lines.append("")
    if behaviors:
        lines.append(f"  {theme.badge_warn()} {theme.bold('Notable API Behaviors:')}")
        rows = []
        for b in behaviors:
            sev = b["severity"]
            sev_colored = (
                theme.red(sev) if sev == "HIGH"
                else (
                    theme.yellow(sev) if sev == "MEDIUM"
                    else (theme.dim(sev) if sev == "GO_RUNTIME" else theme.cyan(sev))
                )
            )
            syms_str = ", ".join(b["symbols"][:10])
            if len(b["symbols"]) > 10:
                syms_str += f" (+{len(b['symbols']) - 10})"
            rows.append([sev_colored, b["category"], syms_str])
        lines.extend(render_table(["Sev", "Category", "Matched Symbols"], rows, theme))

    if anomalies:
        lines.append("")
        lines.append(f"  {theme.badge_warn()} {theme.bold('Executable Instruction Anomalies:')}")
        rows = [
            [
                theme.cyan(a["address"]),
                a["section"],
                theme.red(f"{a['mnemonic']} {a['op_str']}".strip()),
                a["reason"],
            ]
            for a in anomalies
        ]
        lines.extend(render_table(["Address", "Section", "Instruction", "Recon Note"], rows, theme))

    if indirect_jumps:
        lines.append("")
        lines.append(f"  {theme.badge_warn()} {theme.bold('Indirect Jump / Switch / VM Dispatcher Candidates:')}")
        lines.append(f"    {', '.join(indirect_jumps[:8])}")

    # Next Phase (if present): Crypto, Blobs, Embedded Magic, Archive, WASM, Strings
    crypto_hits = recon.get("crypto_constants", [])
    blobs = recon.get("entropy_blobs", [])
    magic_hits = recon.get("embedded_magic", [])
    arch = recon.get("archive")
    wasm_info = recon.get("wasm")
    istrs = recon.get("interesting_strings", [])
    if crypto_hits or blobs or magic_hits or arch or wasm_info or istrs:
        lines.append(render_phase_header(phase, "Crypto, Payloads, Archive & Strings Recon", theme))
        phase += 1
    if wasm_info:
        lines.append(render_section_header("WebAssembly (WASM) Module", theme).lstrip("\n"))
        lines.extend(
            render_kv_block(
                [
                    ("Sections", ", ".join(wasm_info["sections"]) or "None"),
                    ("Exports", ", ".join(wasm_info["exports"]) or "None"),
                ],
                theme,
            )
        )
    if crypto_hits:
        lines.append(render_section_header(f"Crypto & Encoding Constants ({len(crypto_hits)})", theme).lstrip("\n"))
        rows = [
            [
                f"0x{c['offset']:06x}",
                f"0x{c['vaddr']:08x}" if c["vaddr"] is not None else "-",
                c["section"],
                theme.yellow(c["name"]),
                c["category"],
            ]
            for c in crypto_hits
        ]
        lines.extend(render_table(["Offset", "VAddr", "Section", "Constant", "Category"], rows, theme))

    # High-Entropy Blobs
    blobs = recon.get("entropy_blobs", [])
    if blobs:
        lines.append(render_section_header(f"High-Entropy / Encrypted Blob Candidates ({len(blobs)})", theme))
        has_xref = any("xref_label" in b for b in blobs[:8])
        rows = []
        for b in blobs[:8]:
            row = [
                f"0x{b['offset']:06x}..0x{b['end']:06x}",
                f"0x{b['vaddr']:08x}" if b["vaddr"] is not None else "-",
                b["section"],
                f"{b['size']} B",
                _color_entropy(b["entropy"], theme),
            ]
            if has_xref:
                xl = b.get("xref_label", "-")
                row.append(theme.bold_cyan(xl) if b.get("xref_main") else theme.dim(xl))
            row.append(theme.dim(b["preview_hex"][:32]))
            rows.append(row)
        headers = ["File Range", "VAddr", "Section", "Size", "Entropy"]
        if has_xref:
            headers.append("XREF / Origin")
        headers.append("First Bytes")
        lines.extend(render_table(headers, rows, theme))

    # Embedded Magic
    magic_hits = recon.get("embedded_magic", [])
    if magic_hits:
        lines.append(render_section_header(f"Embedded File / Stream Signatures ({len(magic_hits)})", theme))
        rows = [
            [
                f"0x{m['offset']:06x}",
                f"0x{m['vaddr']:08x}" if m["vaddr"] is not None else "-",
                m["section"],
                theme.bold_cyan(m["type"]),
                m["description"],
            ]
            for m in magic_hits[:10]
        ]
        lines.extend(render_table(["Offset", "VAddr", "Section", "Type", "Description"], rows, theme))

    # Archive / Android APK Recon
    arch = recon.get("archive")
    if arch:
        lines.append(render_section_header(f"Archive / Mobile Recon ({arch['kind']})", theme))
        arch_items = [
            ("Total Entries", str(arch["total_entries"])),
            ("AndroidManifest.xml", "Present" if arch["has_manifest"] else "No"),
            ("DEX Files", ", ".join(arch["dex_files"]) if arch["dex_files"] else "None"),
            ("Native .so Count", str(len(arch["native_libs"]))),
        ]
        if arch.get("mobile_framework"):
            arch_items.insert(0, ("Mobile Framework", theme.bold_cyan(arch["mobile_framework"]["name"])))
        lines.extend(render_kv_block(arch_items, theme))
        if arch["packer_hints"]:
            for ph in arch["packer_hints"]:
                lines.append(f"  {theme.red('[!]')} {ph}")
        if arch.get("nested_executables"):
            lines.append(f"  {theme.cyan('Nested binaries/archives:')} {', '.join(arch['nested_executables'][:10])}")
        if arch["native_libs"]:
            lines.append(f"  {theme.dim('Native libs:')} {', '.join(arch['native_libs'][:10])}")
        if arch.get("manifest_components"):
            lines.append(f"  {theme.cyan('Manifest components/URIs:')} {', '.join(arch['manifest_components'][:8])}")
        if arch.get("native_elf_checks"):
            for nelf in arch["native_elf_checks"]:
                beh_str = ", ".join(b["category"] for b in nelf["behaviors"]) or "Standard"
                lines.append(
                    f"  {theme.cyan('Native ELF:')} {nelf['entry']} "
                    f"({nelf['arch']} | {nelf['stripped']} | APIs: {beh_str})"
                )
        nested = arch.get("nested_apk")
        if nested:
            lines.append(render_section_header(f"Nested APK ({nested['source_entry']})", theme))
            lines.extend(
                render_kv_block(
                    [
                        ("Total Entries", str(nested["total_entries"])),
                        ("AndroidManifest.xml", "Present" if nested["has_manifest"] else "No"),
                        ("DEX Files", ", ".join(nested["dex_files"]) if nested["dex_files"] else "None"),
                        ("Native .so Count", str(len(nested["native_libs"]))),
                    ],
                    theme,
                )
            )
            for ph in nested.get("packer_hints", []):
                lines.append(f"  {theme.red('[!]')} {ph}")
            if nested["native_libs"]:
                lines.append(f"  {theme.dim('Native libs:')} {', '.join(nested['native_libs'][:10])}")

    # Interesting Strings preview
    istrs = recon.get("interesting_strings", [])
    if istrs:
        lines.append(render_section_header(f"High-Signal Strings (Top {min(len(istrs), 15)})", theme))
        rows = [
            [
                f"0x{s['offset']:06x}",
                s["section"],
                theme.yellow(",".join(s["tags"])),
                s["value"][:80],
            ]
            for s in istrs[:15]
        ]
        lines.extend(render_table(["Offset", "Section", "Tags", "String"], rows, theme))

    return "\n".join(lines), phase


def format_recon(recon: dict[str, Any], theme: Theme) -> str:
    """Render deep national-CTF reverse engineering reconnaissance report."""
    text, _next_phase = format_recon_with_phase(recon, theme)
    return text


def format_strings(strings_list: list[dict[str, Any]], theme: Theme, limit: int | None = None) -> str:
    """Render extracted strings with offsets, section names, and recon tags."""
    total = len(strings_list)
    shown = strings_list[:limit] if limit is not None else strings_list
    lines = [render_section_header(f"Strings ({total})", theme).lstrip("\n")]
    rows = [
        [
            f"0x{s['offset']:06x}",
            f"0x{s['vaddr']:08x}" if s["vaddr"] is not None else "-",
            s["section"],
            s["encoding"],
            theme.yellow(",".join(s["tags"])) if s["tags"] else theme.dim("-"),
            s["value"][:100],
        ]
        for s in shown
    ]
    lines.extend(render_table(["Offset", "VAddr", "Section", "Enc", "Tags", "Value"], rows, theme))
    if limit is not None and total > limit:
        lines.append(f"  {theme.dim(f'... showing {limit} of {total} strings (use --limit 0 for all)')}")
    return "\n".join(lines)


def format_crypto(
    crypto_hits: list[dict[str, Any]],
    magic_hits: list[dict[str, Any]],
    theme: Theme,
) -> str:
    """Render cryptographic constants and embedded magic signature scan."""
    lines = [render_section_header(f"Cryptographic & Encoding Constants ({len(crypto_hits)})", theme).lstrip("\n")]
    rows = [
        [
            f"0x{c['offset']:06x}",
            f"0x{c['vaddr']:08x}" if c["vaddr"] is not None else "-",
            c["section"],
            theme.yellow(c["name"]),
            c["category"],
        ]
        for c in crypto_hits
    ]
    lines.extend(render_table(["Offset", "VAddr", "Section", "Constant", "Category"], rows, theme))

    lines.append(render_section_header(f"Embedded Magic Signatures ({len(magic_hits)})", theme))
    mrows = [
        [
            f"0x{m['offset']:06x}",
            f"0x{m['vaddr']:08x}" if m["vaddr"] is not None else "-",
            m["section"],
            theme.bold_cyan(m["type"]),
            m["description"],
        ]
        for m in magic_hits
    ]
    lines.extend(render_table(["Offset", "VAddr", "Section", "Type", "Description"], mrows, theme))
    return "\n".join(lines)


def format_blobs(blobs: list[dict[str, Any]], magic_hits: list[dict[str, Any]], theme: Theme) -> str:
    """Render high-entropy blobs and embedded payload offsets."""
    lines = [render_section_header(f"High-Entropy Regions ({len(blobs)})", theme).lstrip("\n")]
    has_xref = any("xref_label" in b for b in blobs)
    rows = []
    for b in blobs:
        row = [
            f"0x{b['offset']:06x}..0x{b['end']:06x}",
            f"0x{b['vaddr']:08x}" if b["vaddr"] is not None else "-",
            b["section"],
            f"{b['size']} B (0x{b['size']:x})",
            _color_entropy(b["entropy"], theme),
        ]
        if has_xref:
            xl = b.get("xref_label", "-")
            row.append(theme.bold_cyan(xl) if b.get("xref_main") else theme.dim(xl))
        row.append(theme.dim(b["preview_hex"][:35]))
        rows.append(row)
    headers = ["File Range", "VAddr", "Section", "Size", "Entropy"]
    if has_xref:
        headers.append("XREF / Origin")
    headers.append("Preview (Hex)")
    lines.extend(render_table(headers, rows, theme))

    if magic_hits:
        lines.append(render_section_header(f"Embedded Magic Signatures ({len(magic_hits)})", theme))
        mrows = [
            [
                f"0x{m['offset']:06x}",
                f"0x{m['vaddr']:08x}" if m["vaddr"] is not None else "-",
                m["section"],
                theme.bold_cyan(m["type"]),
                m["description"],
            ]
            for m in magic_hits
        ]
        lines.extend(render_table(["Offset", "VAddr", "Section", "Type", "Description"], mrows, theme))
    return "\n".join(lines)


def format_xform(res: dict[str, Any], theme: Theme) -> str:
    """Render static byte transform result."""
    lines = [render_section_header("Byte Transform Result", theme).lstrip("\n")]
    items = [
        ("Input", res["input_file"]),
        ("Pipeline", res["pipeline"]),
        ("Output Size", f"{res['output_size']} B"),
        ("Detected Format", f"{theme.bold_cyan(res['detected_format'])} — {res['detected_description']}"),
        ("Entropy", f"{_color_entropy(res['entropy'], theme)} / 8.00"),
        ("Hex Preview", res["preview_hex"]),
        ("ASCII Preview", res["preview_ascii"]),
    ]
    if res.get("written_to"):
        items.append(("Saved To", theme.green(res["written_to"])))
    lines.extend(render_kv_block(items, theme))
    return "\n".join(lines)


