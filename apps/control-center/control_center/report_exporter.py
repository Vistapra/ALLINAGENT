#!/usr/bin/env python3
"""Deterministic Cross-Platform PDF + DOCX Report Exporter (`FEAT-28`).

Used by `@compliance` (`Report & Compliance Agent`), Office Bridge Web download endpoints,
and Telegram report delivery (`sendDocument`) to convert structured Markdown audit/compliance
reports into `.pdf` and `.docx` deliverables with:
- Zero external LibreOffice / `soffice` requirement.
- High-fidelity formatting via `reportlab` (PDF) and `python-docx` (DOCX) when installed.
- Clean zero-dependency Python stdlib fallbacks (spec-compliant PDF-1.4 writer + OpenXML
  `.docx` ZIP generator) so report export succeeds deterministically even before optional
  wheels are installed.
- Automatic secret redaction (`sanitize_text`) and credential-file input rejection.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import textwrap
import zipfile
from html import escape as xml_escape
from pathlib import Path
from typing import Any

_PKG_ROOT = str(Path(__file__).resolve().parents[1])
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from control_center.paths import REPORTS_DIR
from control_center.vulnclaw_defensive import sanitize_text

HEADING_RE = re.compile(r"^(#{1,4})\s+(.+?)\s*$")
BULLET_RE = re.compile(r"^\s*[-*+]\s+(.+?)\s*$")
ORDERED_RE = re.compile(r"^\s*(\d+)\.\s+(.+?)\s*$")
HR_RE = re.compile(r"^\s*(?:---+|\*\*\*+|___+)\s*$")
TABLE_SEP_RE = re.compile(r"^\s*\|?(?:\s*:?-{2,}:?\s*\|)+\s*:?-{2,}:?\s*\|?\s*$")
INLINE_TOKEN_RE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


def _assert_safe_report_source(md_file: Path) -> None:
    lower = md_file.name.lower()
    if lower == ".env" or lower.startswith(".env.") or "auth.json" in lower or "secret" in lower:
        raise PermissionError(f"Refusing to export protected file: {md_file}")
    if not md_file.is_file():
        raise FileNotFoundError(f"Markdown report source not found: {md_file}")


def _strip_inline_md(text: str) -> str:
    s = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    s = re.sub(r"`([^`]+)`", r"\1", s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", s)
    return s.strip()


def _to_reportlab_markup(text: str) -> str:
    """Convert inline `**bold**` and `` `code` `` into safe XML-escaped ReportLab Paragraph markup."""
    normalized = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    parts: list[str] = []
    last = 0
    for m in INLINE_TOKEN_RE.finditer(normalized):
        if m.start() > last:
            parts.append(xml_escape(normalized[last : m.start()]))
        tok = m.group(0)
        if tok.startswith("**") and tok.endswith("**"):
            parts.append(f"<b>{xml_escape(tok[2:-2])}</b>")
        elif tok.startswith("`") and tok.endswith("`"):
            parts.append(f'<font name="Courier">{xml_escape(tok[1:-1])}</font>')
        last = m.end()
    if last < len(normalized):
        parts.append(xml_escape(normalized[last:]))
    return "".join(parts)


def parse_markdown_blocks(md_text: str) -> list[dict[str, Any]]:
    """Parse Markdown text into structured blocks (`heading`, `paragraph`, `list`, `code`, `table`, `quote`, `hr`)."""
    lines = md_text.splitlines()
    blocks: list[dict[str, Any]] = []
    i = 0
    n = len(lines)

    while i < n:
        ln = lines[i]
        stripped = ln.strip()

        if not stripped:
            i += 1
            continue

        # Fenced code block
        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            i += 1
            code_lines: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            if i < n:
                i += 1
            blocks.append({"type": "code", "lang": lang, "text": "\n".join(code_lines)})
            continue

        # Horizontal rule
        if HR_RE.match(stripped):
            blocks.append({"type": "hr"})
            i += 1
            continue

        # Heading
        hm = HEADING_RE.match(ln)
        if hm:
            blocks.append({"type": "heading", "level": len(hm.group(1)), "text": hm.group(2).strip()})
            i += 1
            continue

        # Pipe table
        if "|" in stripped and (i + 1 < n) and TABLE_SEP_RE.match(lines[i + 1]):
            def _split_row(row_str: str) -> list[str]:
                r = row_str.strip().strip("|")
                return [c.strip() for c in r.split("|")]

            headers = _split_row(lines[i])
            i += 2  # skip header + separator
            rows: list[list[str]] = []
            while i < n and "|" in lines[i] and lines[i].strip():
                row_cells = _split_row(lines[i])
                if len(row_cells) < len(headers):
                    row_cells.extend([""] * (len(headers) - len(row_cells)))
                rows.append(row_cells[: len(headers)])
                i += 1
            blocks.append({"type": "table", "headers": headers, "rows": rows})
            continue

        # Blockquote
        if stripped.startswith(">"):
            q_lines: list[str] = []
            while i < n and lines[i].strip().startswith(">"):
                q_lines.append(lines[i].strip().lstrip(">").strip())
                i += 1
            blocks.append({"type": "quote", "text": " ".join(q_lines)})
            continue

        # Bullet or numbered list
        bm = BULLET_RE.match(ln)
        om = ORDERED_RE.match(ln)
        if bm or om:
            ordered = bool(om)
            items: list[str] = []
            while i < n:
                b_sub = BULLET_RE.match(lines[i])
                o_sub = ORDERED_RE.match(lines[i])
                if ordered and o_sub:
                    items.append(o_sub.group(2).strip())
                    i += 1
                elif not ordered and b_sub:
                    items.append(b_sub.group(1).strip())
                    i += 1
                else:
                    break
            blocks.append({"type": "list", "ordered": ordered, "items": items})
            continue

        # Paragraph
        p_lines: list[str] = [stripped]
        i += 1
        while i < n:
            nxt = lines[i].strip()
            if (
                not nxt
                or nxt.startswith(("```", "#", ">"))
                or HR_RE.match(nxt)
                or BULLET_RE.match(lines[i])
                or ORDERED_RE.match(lines[i])
                or ("|" in nxt and (i + 1 < n) and TABLE_SEP_RE.match(lines[i + 1]))
            ):
                break
            p_lines.append(nxt)
            i += 1
        blocks.append({"type": "paragraph", "text": " ".join(p_lines)})

    return blocks


# --- PDF Rendering (ReportLab Primary + Stdlib PDF-1.4 Fallback) ---

def _render_pdf_reportlab(blocks: list[dict[str, Any]], pdf_path: Path, title: str) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    h_styles = {
        1: ParagraphStyle("H1Custom", parent=styles["Heading1"], fontSize=16, leading=20, spaceBefore=10, spaceAfter=6, textColor=colors.HexColor("#0F172A")),
        2: ParagraphStyle("H2Custom", parent=styles["Heading2"], fontSize=13, leading=17, spaceBefore=9, spaceAfter=4, textColor=colors.HexColor("#1E293B")),
        3: ParagraphStyle("H3Custom", parent=styles["Heading3"], fontSize=11, leading=14, spaceBefore=7, spaceAfter=3, textColor=colors.HexColor("#334155")),
        4: ParagraphStyle("H4Custom", parent=styles["Heading4"], fontSize=10, leading=13, spaceBefore=6, spaceAfter=2, textColor=colors.HexColor("#475569")),
    }
    body_style = ParagraphStyle("BodyCustom", parent=styles["BodyText"], fontSize=9.5, leading=13.5, spaceAfter=5)
    bullet_style = ParagraphStyle("BulletCustom", parent=body_style, leftIndent=14, spaceAfter=3)
    quote_style = ParagraphStyle("QuoteCustom", parent=body_style, leftIndent=14, textColor=colors.HexColor("#475569"), fontName="Helvetica-Oblique")
    code_style = ParagraphStyle("CodeCustom", fontName="Courier", fontSize=8, leading=10.5, leftIndent=8, rightIndent=8, backColor=colors.HexColor("#F1F5F9"), borderPadding=5, spaceAfter=6)
    cell_style = ParagraphStyle("CellCustom", parent=body_style, fontSize=8.5, leading=11, spaceAfter=0)
    cell_hdr_style = ParagraphStyle("CellHdrCustom", parent=cell_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#0F172A"))

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=title,
        author="ALLINAGENT Report & Compliance Agent",
    )

    story: list[Any] = []
    has_h1 = any(b["type"] == "heading" and b["level"] == 1 for b in blocks)
    if not has_h1 and title:
        story.append(Paragraph(xml_escape(title), h_styles[1]))
        story.append(Spacer(1, 4))

    usable_width = A4[0] - (36 * mm)

    for blk in blocks:
        btype = blk["type"]
        if btype == "heading":
            lvl = min(4, max(1, int(blk["level"])))
            story.append(Paragraph(_to_reportlab_markup(blk["text"]), h_styles[lvl]))
        elif btype == "paragraph":
            story.append(Paragraph(_to_reportlab_markup(blk["text"]), body_style))
        elif btype == "quote":
            story.append(Paragraph(_to_reportlab_markup(blk["text"]), quote_style))
        elif btype == "hr":
            story.append(Spacer(1, 3))
            story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#CBD5E1")))
            story.append(Spacer(1, 4))
        elif btype == "list":
            for idx, item in enumerate(blk["items"], 1):
                prefix = f"{idx}. " if blk["ordered"] else "• "
                story.append(Paragraph(prefix + _to_reportlab_markup(item), bullet_style))
            story.append(Spacer(1, 3))
        elif btype == "code":
            wrapped_lines = []
            for raw_ln in blk["text"].splitlines() or [""]:
                wrapped_lines.extend(textwrap.wrap(raw_ln, width=92, replace_whitespace=False) or [""])
            story.append(Preformatted("\n".join(wrapped_lines), code_style))
        elif btype == "table":
            headers = blk["headers"]
            col_count = max(1, len(headers))
            col_w = usable_width / col_count
            t_data = [[Paragraph(_to_reportlab_markup(h), cell_hdr_style) for h in headers]]
            for r in blk["rows"]:
                t_data.append([Paragraph(_to_reportlab_markup(c), cell_style) for c in r])
            tbl = Table(t_data, colWidths=[col_w] * col_count, repeatRows=1)
            tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(tbl)
            story.append(Spacer(1, 6))

    if not story:
        story.append(Paragraph(xml_escape(title or "Compliance Report"), body_style))

    def _draw_footer(canvas: Any, doc_obj: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(18 * mm, 10 * mm, "ALLINAGENT Compliance & Audit Report")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc_obj.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)


def _pdf_escape(text: str) -> str:
    safe_ascii = text.encode("latin-1", errors="replace").decode("latin-1")
    return safe_ascii.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _render_pdf_stdlib(blocks: list[dict[str, Any]], pdf_path: Path, title: str) -> None:
    """Zero-dependency spec-compliant PDF-1.4 writer fallback."""
    lines_out: list[tuple[str, int]] = []  # (text, font_size)
    has_h1 = any(b["type"] == "heading" and b["level"] == 1 for b in blocks)
    if not has_h1 and title:
        lines_out.append((title, 15))
        lines_out.append(("", 10))

    for blk in blocks:
        btype = blk["type"]
        if btype == "heading":
            sz = {1: 15, 2: 13, 3: 11, 4: 10}.get(blk["level"], 11)
            lines_out.append(("", 6))
            for w in textwrap.wrap(_strip_inline_md(blk["text"]), width=78) or [""]:
                lines_out.append((w, sz))
        elif btype in ("paragraph", "quote"):
            prefix = "> " if btype == "quote" else ""
            for w in textwrap.wrap(prefix + _strip_inline_md(blk["text"]), width=88) or [""]:
                lines_out.append((w, 10))
            lines_out.append(("", 6))
        elif btype == "hr":
            lines_out.append(("-" * 72, 9))
        elif btype == "list":
            for idx, item in enumerate(blk["items"], 1):
                lead = f"{idx}. " if blk["ordered"] else "* "
                wrapped = textwrap.wrap(_strip_inline_md(item), width=84) or [""]
                lines_out.append((lead + wrapped[0], 10))
                for cont in wrapped[1:]:
                    lines_out.append(("   " + cont, 10))
            lines_out.append(("", 6))
        elif btype == "code":
            for raw_ln in blk["text"].splitlines() or [""]:
                for w in textwrap.wrap(raw_ln, width=86, replace_whitespace=False) or [""]:
                    lines_out.append(("    " + w, 9))
            lines_out.append(("", 6))
        elif btype == "table":
            lines_out.append((" | ".join(_strip_inline_md(h) for h in blk["headers"]), 9))
            lines_out.append(("-" * 72, 9))
            for r in blk["rows"]:
                lines_out.append((" | ".join(_strip_inline_md(c) for c in r), 9))
            lines_out.append(("", 6))

    if not lines_out:
        lines_out.append((title or "Compliance Report", 12))

    # Paginate A4 (595 x 842 pt)
    pages_streams: list[bytes] = []
    cur_ops: list[str] = ["BT"]
    y = 790
    for txt, fsize in lines_out:
        step = fsize + 4
        if y - step < 50:
            cur_ops.append("ET")
            pages_streams.append("\n".join(cur_ops).encode("latin-1"))
            cur_ops = ["BT"]
            y = 790
        if txt:
            cur_ops.append(f"/F1 {fsize} Tf 1 0 0 1 48 {y} Tm ({_pdf_escape(txt)}) Tj")
        y -= step
    cur_ops.append("ET")
    pages_streams.append("\n".join(cur_ops).encode("latin-1"))

    # Object numbering: 1=Catalog, 2=Pages, 3=Font, 4..(3+2*P)=Page+Content pairs
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    kids_refs: list[str] = []
    next_id = 4
    for stream_bytes in pages_streams:
        page_id = next_id
        content_id = next_id + 1
        next_id += 2
        kids_refs.append(f"{page_id} 0 R")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        objects[content_id] = (
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream"
        )
    objects[2] = f"<< /Type /Pages /Count {len(kids_refs)} /Kids [{' '.join(kids_refs)}] >>".encode("ascii")

    total_objs = next_id - 1
    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for oid in range(1, total_objs + 1):
        offsets[oid] = len(buf)
        buf.extend(f"{oid} 0 obj\n".encode("ascii"))
        buf.extend(objects[oid])
        buf.extend(b"\nendobj\n")

    xref_pos = len(buf)
    buf.extend(f"xref\n0 {total_objs + 1}\n".encode("ascii"))
    buf.extend(b"0000000000 65535 f \n")
    for oid in range(1, total_objs + 1):
        buf.extend(f"{offsets[oid]:010d} 00000 n \n".encode("ascii"))
    buf.extend(
        (
            f"trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("ascii")
    )
    pdf_path.write_bytes(bytes(buf))


# --- DOCX Rendering (python-docx Primary + Stdlib OpenXML Fallback) ---

def _add_formatted_runs_docx(paragraph: Any, text: str, font_cls_pt: Any) -> None:
    normalized = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    last = 0
    for m in INLINE_TOKEN_RE.finditer(normalized):
        if m.start() > last:
            paragraph.add_run(normalized[last : m.start()])
        tok = m.group(0)
        if tok.startswith("**") and tok.endswith("**"):
            r = paragraph.add_run(tok[2:-2])
            r.bold = True
        elif tok.startswith("`") and tok.endswith("`"):
            r = paragraph.add_run(tok[1:-1])
            r.font.name = "Courier New"
            r.font.size = font_cls_pt(9.5)
        last = m.end()
    if last < len(normalized):
        paragraph.add_run(normalized[last:])


def _render_docx_python_docx(blocks: list[dict[str, Any]], docx_path: Path, title: str) -> None:
    import docx
    from docx.shared import Pt

    doc = docx.Document()
    doc.core_properties.title = title
    doc.core_properties.author = "ALLINAGENT Report & Compliance Agent"

    has_h1 = any(b["type"] == "heading" and b["level"] == 1 for b in blocks)
    if not has_h1 and title:
        doc.add_heading(title, level=1)

    for blk in blocks:
        btype = blk["type"]
        if btype == "heading":
            lvl = min(4, max(1, int(blk["level"])))
            doc.add_heading(_strip_inline_md(blk["text"]), level=lvl)
        elif btype == "paragraph":
            p = doc.add_paragraph()
            _add_formatted_runs_docx(p, blk["text"], Pt)
        elif btype == "quote":
            p = doc.add_paragraph()
            r = p.add_run(_strip_inline_md(blk["text"]))
            r.italic = True
        elif btype == "hr":
            doc.add_paragraph("—" * 40)
        elif btype == "list":
            style_name = "List Number" if blk["ordered"] else "List Bullet"
            for item in blk["items"]:
                p = doc.add_paragraph(style=style_name)
                _add_formatted_runs_docx(p, item, Pt)
        elif btype == "code":
            p = doc.add_paragraph()
            r = p.add_run(blk["text"])
            r.font.name = "Courier New"
            r.font.size = Pt(8.5)
        elif btype == "table":
            headers = blk["headers"]
            col_count = max(1, len(headers))
            tbl = doc.add_table(rows=1 + len(blk["rows"]), cols=col_count)
            tbl.style = "Table Grid"
            for ci, h_txt in enumerate(headers):
                cell_p = tbl.rows[0].cells[ci].paragraphs[0]
                run = cell_p.add_run(_strip_inline_md(h_txt))
                run.bold = True
            for ri, row_vals in enumerate(blk["rows"], start=1):
                for ci, c_txt in enumerate(row_vals[:col_count]):
                    cell_p = tbl.rows[ri].cells[ci].paragraphs[0]
                    _add_formatted_runs_docx(cell_p, c_txt, Pt)

    doc.save(str(docx_path))


def _render_docx_stdlib(blocks: list[dict[str, Any]], docx_path: Path, title: str) -> None:
    """Zero-dependency OpenXML `.docx` ZIP archive fallback."""
    body_xml: list[str] = []

    def _w_p(text: str, bold: bool = False, size_half_pt: int = 21) -> str:
        rpr = f"<w:rPr>{'<w:b/>' if bold else ''}<w:sz w:val=\"{size_half_pt}\"/></w:rPr>"
        return f"<w:p><w:r>{rpr}<w:t xml:space=\"preserve\">{xml_escape(text)}</w:t></w:r></w:p>"

    has_h1 = any(b["type"] == "heading" and b["level"] == 1 for b in blocks)
    if not has_h1 and title:
        body_xml.append(_w_p(title, bold=True, size_half_pt=32))

    for blk in blocks:
        btype = blk["type"]
        if btype == "heading":
            sz = {1: 32, 2: 26, 3: 23, 4: 21}.get(blk["level"], 22)
            body_xml.append(_w_p(_strip_inline_md(blk["text"]), bold=True, size_half_pt=sz))
        elif btype in ("paragraph", "quote"):
            body_xml.append(_w_p(_strip_inline_md(blk["text"])))
        elif btype == "hr":
            body_xml.append(_w_p("—" * 40))
        elif btype == "list":
            for idx, it in enumerate(blk["items"], 1):
                lead = f"{idx}. " if blk["ordered"] else "• "
                body_xml.append(_w_p(lead + _strip_inline_md(it)))
        elif btype == "code":
            for ln in blk["text"].splitlines() or [""]:
                body_xml.append(_w_p(ln, size_half_pt=18))
        elif btype == "table":
            rows_xml: list[str] = []
            for ri, row_cells in enumerate([blk["headers"], *blk["rows"]]):
                tcs = "".join(
                    f"<w:tc><w:p><w:r>{'<w:rPr><w:b/></w:rPr>' if ri == 0 else ''}"
                    f"<w:t xml:space=\"preserve\">{xml_escape(_strip_inline_md(c))}</w:t></w:r></w:p></w:tc>"
                    for c in row_cells
                )
                rows_xml.append(f"<w:tr>{tcs}</w:tr>")
            body_xml.append(f"<w:tbl>{''.join(rows_xml)}</w:tbl>")

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{''.join(body_xml)}<w:sectPr/></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    with zipfile.ZipFile(str(docx_path), "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("word/document.xml", document_xml)


def export_markdown_to_pdf(
    md_path: str | Path,
    pdf_path: str | Path,
    *,
    title: str | None = None,
    force_stdlib: bool = False,
) -> dict[str, Any]:
    md_file = Path(md_path).resolve()
    _assert_safe_report_source(md_file)
    out_pdf = Path(pdf_path).resolve()
    out_pdf.parent.mkdir(parents=True, exist_ok=True)

    safe_md = sanitize_text(md_file.read_text(encoding="utf-8", errors="replace"))
    blocks = parse_markdown_blocks(safe_md)
    doc_title = title or next(
        (_strip_inline_md(b["text"]) for b in blocks if b["type"] == "heading"),
        md_file.stem,
    )

    engine = "stdlib_pdf14"
    if not force_stdlib:
        try:
            _render_pdf_reportlab(blocks, out_pdf, doc_title)
            engine = "reportlab"
        except ImportError:
            _render_pdf_stdlib(blocks, out_pdf, doc_title)
    else:
        _render_pdf_stdlib(blocks, out_pdf, doc_title)

    pdf_bytes = out_pdf.read_bytes()
    return {
        "pdf_path": str(out_pdf),
        "pdf_size_bytes": len(pdf_bytes),
        "pdf_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
        "pdf_engine": engine,
    }


def export_markdown_to_docx(
    md_path: str | Path,
    docx_path: str | Path,
    *,
    title: str | None = None,
    force_stdlib: bool = False,
) -> dict[str, Any]:
    md_file = Path(md_path).resolve()
    _assert_safe_report_source(md_file)
    out_docx = Path(docx_path).resolve()
    out_docx.parent.mkdir(parents=True, exist_ok=True)

    safe_md = sanitize_text(md_file.read_text(encoding="utf-8", errors="replace"))
    blocks = parse_markdown_blocks(safe_md)
    doc_title = title or next(
        (_strip_inline_md(b["text"]) for b in blocks if b["type"] == "heading"),
        md_file.stem,
    )

    engine = "stdlib_ooxml"
    if not force_stdlib:
        try:
            _render_docx_python_docx(blocks, out_docx, doc_title)
            engine = "python-docx"
        except ImportError:
            _render_docx_stdlib(blocks, out_docx, doc_title)
    else:
        _render_docx_stdlib(blocks, out_docx, doc_title)

    docx_bytes = out_docx.read_bytes()
    return {
        "docx_path": str(out_docx),
        "docx_size_bytes": len(docx_bytes),
        "docx_sha256": hashlib.sha256(docx_bytes).hexdigest(),
        "docx_engine": engine,
    }


def export_markdown_to_pdf_and_docx(
    md_path: str | Path,
    out_dir: str | Path | None = None,
    *,
    base_name: str | None = None,
    title: str | None = None,
    deliver_telegram: bool = False,
    force_stdlib: bool = False,
) -> dict[str, Any]:
    """Deterministically export a Markdown report into both `.pdf` and `.docx` (`FEAT-28`)."""
    md_file = Path(md_path).resolve()
    _assert_safe_report_source(md_file)
    target_dir = Path(out_dir).resolve() if out_dir is not None else REPORTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", (base_name or md_file.stem)).strip("-") or "compliance-report"
    pdf_path = target_dir / f"{stem}.pdf"
    docx_path = target_dir / f"{stem}.docx"

    pdf_info = export_markdown_to_pdf(md_file, pdf_path, title=title, force_stdlib=force_stdlib)
    docx_info = export_markdown_to_docx(md_file, docx_path, title=title, force_stdlib=force_stdlib)

    result: dict[str, Any] = {
        "ok": True,
        "source_markdown": str(md_file),
        "output_dir": str(target_dir),
        **pdf_info,
        **docx_info,
        "web_download_urls": {
            "pdf": f"/api/company/reports/download/{pdf_path.name}",
            "docx": f"/api/company/reports/download/{docx_path.name}",
        },
    }

    if deliver_telegram:
        from control_center.workflow_engine import send_owner_telegram_document

        result["telegram_delivery"] = {
            "pdf": send_owner_telegram_document(pdf_path, caption=f"📄 Compliance Report (PDF): {pdf_path.name}"),
            "docx": send_owner_telegram_document(docx_path, caption=f"📝 Compliance Report (DOCX): {docx_path.name}"),
        }

    return result


def main() -> int:
    import json

    parser = argparse.ArgumentParser(description="Export a Markdown compliance/audit report to deterministic PDF and DOCX.")
    parser.add_argument("markdown_file", help="Path to source Markdown (.md) report")
    parser.add_argument("--out-dir", default=None, help="Output directory (defaults to ALLINAGENT reports dir)")
    parser.add_argument("--base-name", default=None, help="Override output filename stem")
    parser.add_argument("--title", default=None, help="Optional document title override")
    parser.add_argument("--deliver-telegram", action="store_true", help="Deliver PDF & DOCX to configured Owner Telegram")
    parser.add_argument("--force-stdlib", action="store_true", help="Force stdlib PDF/DOCX fallback writers")
    args = parser.parse_args()

    res = export_markdown_to_pdf_and_docx(
        args.markdown_file,
        args.out_dir,
        base_name=args.base_name,
        title=args.title,
        deliver_telegram=args.deliver_telegram,
        force_stdlib=args.force_stdlib,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
