"""Closed, data-only renderers. Never interpret caller-supplied templates or URLs."""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..models import ServiceReportInstance
from ..report_schemas import ReportExportFormat, ServiceReportRender, RetainedProofReportRender
from .report_instances import canonical_bytes, instance_material


FONT_SHA256 = "e52dcae020461843035b81c1b46aee7c22cea493f79997165e185be3d8451d1a"
FONT_NAME = "iCheckReportSC"
MAX_EXPORT_BYTES = 4_000_000
HTML_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox"
)
_font_lock = threading.Lock()
_font: TTFont | None = None


@dataclass(frozen=True)
class ReportExport:
    body: bytes
    media_type: str
    extension: str
    renderer: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


def _time(value: datetime | None) -> str:
    if value is None:
        return "No observation"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _number(value: float | None) -> str:
    return "N/A" if value is None else format(value, ".8g")


def _safe_csv(value):
    if not isinstance(value, str):
        return value
    # User-authored labels must not become spreadsheet formulas. Numbers stay numbers.
    first = value.lstrip(" \t\r\n\ufeff\x00")[:1]
    return "'" + value if first in {"=", "+", "-", "@"} or value.startswith(("\t", "\r", "\n")) else value


def _csv(instance: ServiceReportInstance, snapshot: ServiceReportRender) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    keys = [
        "section_key", "title", "service_key", "service_name", "indicator_key", "indicator_name",
        "state", "drift_code", "current_status", "current_value", "unit", "sample_count",
        "minimum", "average", "maximum", "trend", "breach_direction", "warning_threshold",
        "critical_threshold", "first_observed_at", "last_observed_at", "samples_truncated",
    ]
    proof_keys = ["reference_kind", "reference_id", "historical", "grants_future_authority", "recorded_json"] if isinstance(snapshot, RetainedProofReportRender) else []
    writer.writerow(["instance_id", "version_id", "generated_at", "snapshot_sha256", *keys, *proof_keys])
    for section in snapshot.sections:
        values = section.model_dump(mode="json")
        writer.writerow([instance.id, snapshot.version_id, _time(snapshot.generated_at), instance.content_sha256,
                         *[_safe_csv(values[key]) for key in keys], *["" for _key in proof_keys]])
    if proof_keys:
        for proof in snapshot.retained_proofs:
            values = {"section_key": proof.section_key, "title": proof.title}
            writer.writerow([instance.id, snapshot.version_id, _time(snapshot.generated_at), instance.content_sha256,
                *[_safe_csv(values.get(key, "")) for key in keys], proof.reference_kind, str(proof.reference_id),
                "true", "false", canonical_bytes(proof.recorded.model_dump(mode="json")).decode()])
    return ("\ufeff" + stream.getvalue()).encode("utf-8")


def _html(instance: ServiceReportInstance, snapshot: ServiceReportRender) -> bytes:
    def esc(value):
        return html.escape(str(value), quote=True)

    sections = []
    for section in snapshot.sections:
        metrics = "".join(
            f"<td>{esc(_number(value))}</td>"
            for value in (section.current_value, section.minimum, section.average, section.maximum)
        )
        sections.append(
            f"<section><h2>{esc(section.title)}</h2>"
            f"<p>{esc(section.service_key)} / {esc(section.indicator_key)} | "
            f"{esc(section.state)} | {esc(section.current_status)} | Unit: {esc(section.unit or 'none')}</p>"
            "<table><thead><tr><th>Current</th><th>Minimum</th><th>Average</th><th>Maximum</th></tr></thead>"
            f"<tbody><tr>{metrics}</tr></tbody></table>"
            f"<p>Samples: {section.sample_count} | Trend: {esc(section.trend)} | "
            f"Truncated: {str(section.samples_truncated).lower()}</p>"
            f"<p>Observed: {esc(_time(section.first_observed_at))} to {esc(_time(section.last_observed_at))}</p>"
            f"<p>Threshold direction: {esc(section.breach_direction or 'none')} | "
            f"Warning: {esc(_number(section.warning_threshold))} | Critical: {esc(_number(section.critical_threshold))}</p>"
            f"<p>Drift: {esc(section.drift_code or 'none')}</p></section>"
        )
    if isinstance(snapshot, RetainedProofReportRender):
        for proof in snapshot.retained_proofs:
            sections.append(f"<section><h2>{esc(proof.title)}</h2><p>{esc(proof.reference_kind)} / {esc(proof.reference_id)}</p>"
                "<p>Historical retained control-plane record. Grants future authority: false. "
                "Repair causality proven: false. Physical truth automatically verified: false.</p>"
                f"<pre style='white-space:pre-wrap;overflow-wrap:anywhere'>{esc(json.dumps(proof.recorded.model_dump(mode='json'), ensure_ascii=False, indent=2))}</pre></section>")
    document = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{esc(HTML_CSP)}">'
        f"<title>{esc(snapshot.report_title)}</title>"
        "<style>body{font:15px system-ui,sans-serif;color:#193047;margin:40px auto;max-width:900px;padding:0 24px}"
        "h1{font-size:28px}h2{font-size:19px}section{border-top:1px solid #cbd5e1;margin-top:24px;padding-top:12px}"
        "table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border:1px solid #cbd5e1}"
        "th{background:#eef3f8}p{overflow-wrap:anywhere}small{color:#53657a}</style></head><body>"
        f"<small>iCheck | Retained service-health snapshot</small><h1>{esc(snapshot.report_title)}</h1>"
        f"<p>Generated: {esc(_time(snapshot.generated_at))} | Status: {esc(snapshot.overall_status)} | "
        f"Lookback: {snapshot.lookback_minutes} minutes</p>"
        f"<p>{snapshot.section_count} sections | {snapshot.sample_count} samples | "
        f"{snapshot.drifted_section_count} drifted sections</p>"
        f"<p>Instance: {esc(instance.id)} | Version: {snapshot.version} / {esc(snapshot.version_id)}</p>"
        f"<p>Snapshot SHA256: {esc(instance.content_sha256)}</p>"
        f"<p>Artifact SHA256: {esc(snapshot.content_hash)}</p>"
        "<p>This is a saved snapshot, not a live query. N/A and drift states are not healthy results. "
        "Access is rechecked at download; downloaded files remain the recipient's responsibility.</p>"
        + "".join(sections) + "</body></html>"
    )
    return document.encode("utf-8")


def _report_font() -> TTFont:
    global _font
    with _font_lock:
        if _font is None:
            path = Path(__file__).resolve().parent.parent / "assets/report_fonts/NotoSansSC-Regular.ttf"
            if hashlib.sha256(path.read_bytes()).hexdigest() != FONT_SHA256:
                raise ValueError("Packaged report font integrity check failed")
            candidate = TTFont(FONT_NAME, str(path))
            pdfmetrics.registerFont(candidate)
            _font = candidate
        return _font


def _pdf(instance: ServiceReportInstance, snapshot: ServiceReportRender) -> bytes:
    font = _report_font()
    styles = {
        "body": ParagraphStyle("body", fontName=FONT_NAME, fontSize=10, leading=15, spaceAfter=7, wordWrap="CJK"),
        "title": ParagraphStyle("title", fontName=FONT_NAME, fontSize=21, leading=29, spaceAfter=15, wordWrap="CJK"),
        "heading": ParagraphStyle("heading", fontName=FONT_NAME, fontSize=13, leading=19, spaceBefore=13,
                                  spaceAfter=6, keepWithNext=True, wordWrap="CJK"),
        "small": ParagraphStyle("small", fontName=FONT_NAME, fontSize=8, leading=12, spaceAfter=6, wordWrap="CJK"),
    }
    unsupported: set[int] = set()

    def text(value):
        value = str(value)
        if len(value) > 2000:
            raise ValueError("Report document label exceeds its size limit")
        result = []
        for char in value:
            if char in "\r\n\t":
                result.append(" ")
            elif ord(char) < 32 or ord(char) not in font.face.charWidths:
                unsupported.add(ord(char))
                result.append(f"[U+{ord(char):04X}]")
            else:
                result.append(char)
        return html.escape("".join(result), quote=True)

    def p(value, style="body"):
        # ReportLab Paragraph accepts XML, including external images. Only escaped text enters it.
        return Paragraph(text(value), styles[style])

    story = [
        p(snapshot.report_title, "title"),
        p(f"Generated: {_time(snapshot.generated_at)} | Status: {snapshot.overall_status}"),
        p(f"Lookback: {snapshot.lookback_minutes} minutes | Sections: {snapshot.section_count} | "
          f"Samples: {snapshot.sample_count} | Drifted sections: {snapshot.drifted_section_count}"),
        p(f"Instance: {instance.id}", "small"),
        p(f"Artifact version: {snapshot.version} / {snapshot.version_id}", "small"),
        p(f"Artifact SHA256: {snapshot.content_hash}", "small"),
        p("Retained snapshot, not a live query. N/A and drift states are not healthy results. "
          "Access is rechecked at download; downloaded files remain the recipient's responsibility.", "small"),
    ]
    width = A4[0] - 84
    for section in snapshot.sections:
        section_start = len(story)
        story.extend([
            p(section.title, "heading"),
            p(f"{section.service_key} / {section.indicator_key} | {section.state} | "
              f"{section.current_status} | Unit: {section.unit or 'none'}", "small"),
        ])
        table = Table([
            [p(label, "small") for label in ("Current", "Minimum", "Average", "Maximum")],
            [p(_number(value)) for value in (section.current_value, section.minimum, section.average, section.maximum)],
        ], colWidths=[width / 4] * 4, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3f8")),
            ("GRID", (0, 0), (-1, -1), .5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.extend([
            table, Spacer(1, 7),
            p(f"Samples: {section.sample_count} | Trend: {section.trend} | "
              f"Truncated: {str(section.samples_truncated).lower()}", "small"),
            p(f"Observed: {_time(section.first_observed_at)} to {_time(section.last_observed_at)}", "small"),
            p(f"Threshold direction: {section.breach_direction or 'none'} | "
              f"Warning: {_number(section.warning_threshold)} | Critical: {_number(section.critical_threshold)}", "small"),
            p(f"Drift: {section.drift_code or 'none'}", "small"),
        ])
        story[section_start:] = [KeepTogether(story[section_start:])]
    if isinstance(snapshot, RetainedProofReportRender):
        for proof in snapshot.retained_proofs:
            story.extend([p(proof.title, "heading"), p(f"{proof.reference_kind} / {proof.reference_id}", "small"),
                p("Historical retained control-plane record. Grants future authority: false. "
                  "Repair causality proven: false. Physical truth automatically verified: false.", "small")])
            # Complete data-only proof, not a lossy summary. Split long lines
            # into bounded paragraphs so exact JSON cannot break the page box.
            for line in json.dumps(proof.recorded.model_dump(mode="json"), ensure_ascii=False, indent=2).splitlines():
                for start in range(0, max(1, len(line)), 160):
                    story.append(p(line[start:start+160], "small"))
    if unsupported:
        story.append(p("Unsupported characters are shown as Unicode code points: " +
                       ", ".join(f"U+{code:04X}" for code in sorted(unsupported)), "small"))
    buffer = io.BytesIO()

    def page(canvas, doc):
        if doc.page > 30:
            raise ValueError("Report document exceeds its page limit")
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#193047"))
        canvas.setFont(FONT_NAME, 10)
        canvas.drawString(42, A4[1] - 38, "iCheck | Service-health report")
        canvas.setFont(FONT_NAME, 7)
        canvas.drawString(42, 35, f"Snapshot SHA256: {instance.content_sha256}")
        canvas.drawRightString(A4[0] - 42, 22, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=42, rightMargin=42,
                            topMargin=64, bottomMargin=58, invariant=True,
                            title="iCheck retained service-health report", author="iCheck")
    doc.build(story, onFirstPage=page, onLaterPages=page)
    return buffer.getvalue()


def render_report_export(instance: ServiceReportInstance, snapshot: ServiceReportRender,
                         format: ReportExportFormat) -> ReportExport:
    # Caller must verify integrity and current authorization before rendering.
    renderer_version = "v2" if isinstance(snapshot, RetainedProofReportRender) else "v1"
    if format == "json":
        export = ReportExport(canonical_bytes({**instance_material(instance), "content_sha256": instance.content_sha256}),
                              "application/json", "json", f"icheck-report-json-{renderer_version}")
    elif format == "html":
        export = ReportExport(_html(instance, snapshot), "text/html", "html", f"icheck-report-html-{renderer_version}")
    elif format == "csv":
        export = ReportExport(_csv(instance, snapshot), "text/csv", "csv", f"icheck-report-csv-{renderer_version}")
    elif format == "pdf":
        export = ReportExport(_pdf(instance, snapshot), "application/pdf", "pdf",
                              f"icheck-report-pdf-{renderer_version};reportlab={reportlab.Version};font={FONT_SHA256}")
    else:
        raise ValueError("Unsupported report export format")
    if len(export.body) > MAX_EXPORT_BYTES:
        raise ValueError("Report document exceeds its size limit")
    return export
