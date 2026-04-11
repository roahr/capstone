"""
Sec-C HTML Security Scan Report Generator.

Produces a self-contained, professional HTML report designed for presentation
to security stakeholders. Features executive risk assessment, interactive
cascade pipeline visualization, sortable findings table, and analysis
methodology documentation with both expert-level and accessible explanations.

All assets (CSS, JS, SVG icons) are inlined — no external dependencies.
"""

from __future__ import annotations

import html
import json
import logging
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from src.sast.sarif.schema import Finding, ScanResult, Severity, Verdict

logger = logging.getLogger(__name__)


class HTMLReporter:
    """Generates professional HTML security scan reports for Sec-C."""

    ICONS: dict[str, str] = {
        "shield": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
        ),
        "shield-check": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
            '<polyline points="9 12 11 14 15 10"/></svg>'
        ),
        "shield-alert": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
            '<line x1="12" y1="8" x2="12" y2="12"/>'
            '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
        ),
        "code": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>'
        ),
        "network": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/>'
            '<circle cx="18" cy="19" r="3"/>'
            '<line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>'
            '<line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>'
        ),
        "cpu": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<rect x="4" y="4" width="16" height="16" rx="2"/>'
            '<rect x="9" y="9" width="6" height="6"/>'
            '<line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/>'
            '<line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/>'
            '<line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/>'
            '<line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>'
        ),
        "alert-triangle": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86'
            'a2 2 0 0 0-3.42 0z"/>'
            '<line x1="12" y1="9" x2="12" y2="13"/>'
            '<line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
        ),
        "check-circle": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>'
            '<polyline points="22 4 12 14.01 9 11.01"/></svg>'
        ),
        "x-close": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<line x1="18" y1="6" x2="6" y2="18"/>'
            '<line x1="6" y1="6" x2="18" y2="18"/></svg>'
        ),
        "bar-chart": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<line x1="18" y1="20" x2="18" y2="10"/>'
            '<line x1="12" y1="20" x2="12" y2="4"/>'
            '<line x1="6" y1="20" x2="6" y2="14"/></svg>'
        ),
        "filter": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>'
        ),
        "clock": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="12" cy="12" r="10"/>'
            '<polyline points="12 6 12 12 16 14"/></svg>'
        ),
        "file-text": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
            '<polyline points="14 2 14 8 20 8"/>'
            '<line x1="16" y1="13" x2="8" y2="13"/>'
            '<line x1="16" y1="17" x2="8" y2="17"/></svg>'
        ),
        "chevron-right": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<polyline points="9 18 15 12 9 6"/></svg>'
        ),
        "info": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="12" cy="12" r="10"/>'
            '<line x1="12" y1="16" x2="12" y2="12"/>'
            '<line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        ),
        "layers": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<polygon points="12 2 2 7 12 12 22 7 12 2"/>'
            '<polyline points="2 17 12 22 22 17"/>'
            '<polyline points="2 12 12 17 22 12"/></svg>'
        ),
        "target": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/>'
            '<circle cx="12" cy="12" r="2"/></svg>'
        ),
        "activity": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>'
        ),
        "printer": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<polyline points="6 9 6 2 18 2 18 9"/>'
            '<path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5'
            'a2 2 0 0 1-2 2h-2"/>'
            '<rect x="6" y="14" width="12" height="8"/></svg>'
        ),
        "search": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="11" cy="11" r="8"/>'
            '<line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>'
        ),
        "trending-up": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>'
            '<polyline points="17 6 23 6 23 12"/></svg>'
        ),
        "hash": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/>'
            '<line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>'
        ),
        "globe": (
            '<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            'stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>'
            '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10'
            ' 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>'
        ),
    }

    VERDICT_SORT: dict[str, int] = {
        "confirmed": 4, "likely": 3, "potential": 2, "safe": 1,
    }
    SEVERITY_SORT: dict[str, int] = {
        "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
    }

    def __init__(self, auto_open: bool = True):
        self.auto_open = auto_open

    def _icon(self, name: str, size: int = 20, color: str = "currentColor") -> str:
        """Return an inline SVG icon string."""
        return self.ICONS.get(name, "").format(size=size, color=color)

    def generate(self, scan_result: ScanResult, output_path: str | None = None) -> str:
        """Generate an HTML report and optionally open it in a browser.

        Returns the path to the generated HTML file.
        """
        if output_path is None:
            output_dir = Path(tempfile.mkdtemp(prefix="sec-c-report-"))
            output_path = str(output_dir / "report.html")

        html_content = self._render(scan_result)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML report generated: {output_path}")

        if self.auto_open:
            webbrowser.open(f"file://{Path(output_path).resolve()}")

        return output_path

    # ------------------------------------------------------------------
    # Risk assessment
    # ------------------------------------------------------------------

    def _compute_risk_level(self, result: ScanResult) -> tuple[str, str, str]:
        """Compute overall risk assessment: (level, css_color, narrative)."""
        has_confirmed_critical = any(
            f.verdict == Verdict.CONFIRMED
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in result.findings
        )

        if has_confirmed_critical:
            return (
                "CRITICAL",
                "#ef4444",
                "Critical or high-severity vulnerabilities have been confirmed through "
                "multi-stage analysis. Immediate remediation is strongly recommended "
                "before deployment.",
            )
        if result.confirmed_count > 0:
            return (
                "HIGH",
                "#f97316",
                "Confirmed vulnerabilities have been identified. Prioritize remediation "
                "based on severity and exploitability assessment.",
            )
        if result.likely_count > 0:
            return (
                "MEDIUM",
                "#eab308",
                "Likely vulnerabilities have been identified through multi-stage analysis. "
                "Review and verification recommended to determine remediation priority.",
            )
        if result.potential_count > 0:
            return (
                "LOW",
                "#3b82f6",
                "Only potential vulnerabilities detected with lower confidence scores. "
                "Consider review during standard maintenance cycles.",
            )
        return (
            "MINIMAL",
            "#22c55e",
            "No actionable vulnerabilities detected across all analysis stages. "
            "Continue standard security monitoring practices.",
        )

    # ------------------------------------------------------------------
    # Main render orchestrator
    # ------------------------------------------------------------------

    def _render(self, result: ScanResult) -> str:
        """Render the complete HTML report."""
        findings_json = json.dumps(
            [self._finding_to_dict(f) for f in result.findings],
            indent=2,
            default=str,
        )

        total = result.total_findings
        confirmed = result.confirmed_count
        likely = result.likely_count
        potential = result.potential_count
        safe_count = sum(1 for f in result.findings if f.verdict == Verdict.SAFE)
        risk_level, risk_color, risk_narrative = self._compute_risk_level(result)

        cwe_counts: dict[str, int] = {}
        for f in result.findings:
            key = f"{f.cwe_id} ({f.cwe_name})" if f.cwe_name else f.cwe_id
            cwe_counts[key] = cwe_counts.get(key, 0) + 1

        sev_counts = {s.value: 0 for s in Severity}
        for f in result.findings:
            sev_counts[f.severity.value] += 1

        lang_counts: dict[str, int] = {}
        for f in result.findings:
            lang_counts[f.language.value] = lang_counts.get(f.language.value, 0) + 1

        verdict_counts = {
            "confirmed": confirmed,
            "likely": likely,
            "potential": potential,
            "safe": safe_count,
        }

        parts = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="UTF-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
            f"<title>Sec-C &mdash; Security Scan Report &mdash; {html.escape(result.scan_target)}</title>",
            "<style>",
            self._render_css(),
            "</style>",
            "</head>",
            "<body>",
            self._render_accent_bar(),
            self._render_nav(),
            '<div class="container">',
            self._render_header(result, risk_level, risk_color, risk_narrative),
            self._render_metrics(
                total, confirmed, likely, potential, safe_count,
                result.cascade_efficiency,
            ),
            self._render_timeline(result),
            self._render_pipeline(result, total),
            self._render_charts(sev_counts, cwe_counts, lang_counts, total, verdict_counts),
            self._render_findings_section(
                result, total, confirmed, likely, potential, safe_count,
            ),
            self._render_footer(result),
            "</div>",
            self._render_modal(),
            self._render_methodology(),
            "<script>",
            self._render_javascript(findings_json),
            "</script>",
            "</body>",
            "</html>",
        ]
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # HTML sections
    # ------------------------------------------------------------------

    def _render_accent_bar(self) -> str:
        return '<div class="accent-bar"></div>'

    def _render_nav(self) -> str:
        return f"""
<nav class="report-nav" id="reportNav">
    <div class="nav-brand">
        <span>Sec-C</span>
    </div>
    <div class="nav-links">
        <a href="#summary">Summary</a>
        <a href="#pipeline">Pipeline</a>
        <a href="#findings">Findings</a>
    </div>
    <button class="nav-print" onclick="window.print()" title="Print or save as PDF">
        {self._icon('printer', 16)}
        <span>Print Report</span>
    </button>
</nav>"""

    def _render_header(
        self,
        result: ScanResult,
        risk_level: str,
        risk_color: str,
        risk_narrative: str,
    ) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        langs = ", ".join(lang.value for lang in result.languages_detected) or "N/A"
        duration_s = result.scan_duration_ms / 1000

        risk_gauge = self._render_risk_gauge(risk_level, risk_color)

        return f"""
<section class="report-header" id="summary">
    <div class="header-top">
        <div class="header-brand">
            <div>
                <h1>Sec-C</h1>
                <p class="framework-name">Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection</p>
            </div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:center;gap:8px">
            {risk_gauge}
        </div>
    </div>
    <p class="risk-narrative">{risk_narrative}</p>
    <div class="header-meta">
        <div class="meta-item">
            {self._icon('target', 14, '#94a3b8')}
            <span class="meta-label">Target</span>
            <span class="meta-value">{html.escape(result.scan_target)}</span>
        </div>
        <div class="meta-item">
            {self._icon('code', 14, '#94a3b8')}
            <span class="meta-label">Languages</span>
            <span class="meta-value">{html.escape(langs)}</span>
        </div>
        <div class="meta-item">
            {self._icon('clock', 14, '#94a3b8')}
            <span class="meta-label">Duration</span>
            <span class="meta-value">{duration_s:.1f}s</span>
        </div>
        <div class="meta-item">
            {self._icon('file-text', 14, '#94a3b8')}
            <span class="meta-label">Generated</span>
            <span class="meta-value">{timestamp}</span>
        </div>
    </div>
</section>"""

    def _render_metrics(
        self,
        total: int,
        confirmed: int,
        likely: int,
        potential: int,
        safe_count: int,
        efficiency: float,
    ) -> str:
        eff_pct = int(efficiency * 100)
        return f"""
<div class="metrics-grid">
    <div class="metric-card">
        <div class="metric-icon">{self._icon('layers', 22, '#94a3b8')}</div>
        <div class="metric-value" data-target="{total}">0</div>
        <div class="metric-label">Total Findings</div>
    </div>
    <div class="metric-card">
        <div class="metric-icon">{self._icon('shield-alert', 22, '#ef4444')}</div>
        <div class="metric-value" style="color:#ef4444" data-target="{confirmed}">0</div>
        <div class="metric-label">Confirmed</div>
    </div>
    <div class="metric-card">
        <div class="metric-icon">{self._icon('alert-triangle', 22, '#eab308')}</div>
        <div class="metric-value" style="color:#eab308" data-target="{likely}">0</div>
        <div class="metric-label">Likely</div>
    </div>
    <div class="metric-card">
        <div class="metric-icon">{self._icon('search', 22, '#38bdf8')}</div>
        <div class="metric-value" style="color:#38bdf8" data-target="{potential}">0</div>
        <div class="metric-label">Potential</div>
    </div>
    <div class="metric-card">
        <div class="metric-icon">{self._icon('check-circle', 22, '#22c55e')}</div>
        <div class="metric-value" style="color:#22c55e" data-target="{safe_count}">0</div>
        <div class="metric-label">False Positives Filtered</div>
    </div>
    <div class="metric-card">
        <div class="metric-icon">{self._icon('trending-up', 22, '#818cf8')}</div>
        <div class="metric-value" style="color:#818cf8"
            data-target="{eff_pct}" data-suffix="%">0</div>
        <div class="metric-label">Cascade Efficiency</div>
    </div>
</div>"""

    def _render_pipeline(self, result: ScanResult, total: int) -> str:
        sast_pct = result.resolved_at_sast / max(total, 1) * 100
        graph_pct = result.resolved_at_graph / max(total, 1) * 100
        llm_pct = result.resolved_at_llm / max(total, 1) * 100

        # Build stage node data for the SVG
        stages = [
            ("SAST", "Static Analysis", result.resolved_at_sast, f"{sast_pct:.0f}%", "#22c55e"),
            ("Graph", "Neural Analysis", result.resolved_at_graph, f"{graph_pct:.0f}%", "#38bdf8"),
            ("LLM", "Adversarial", result.resolved_at_llm, f"{llm_pct:.0f}%", "#eab308"),
        ]
        if result.unresolved > 0:
            unresolved_pct = result.unresolved / max(total, 1) * 100
            stages.append((
                "Unresolved", "Requires Review",
                result.unresolved, f"{unresolved_pct:.0f}%", "#ef4444",
            ))

        num_stages = len(stages)
        node_w, node_h = 140, 100
        gap = 80
        svg_w = num_stages * node_w + (num_stages - 1) * gap + 40
        svg_h = node_h + 40

        svg_parts = []
        # Draw connector paths with animated dashes and particles
        for idx in range(num_stages - 1):
            x1 = 20 + idx * (node_w + gap) + node_w
            x2 = 20 + (idx + 1) * (node_w + gap)
            y = svg_h // 2
            path_id = f"pipeline-path-{idx}"
            svg_parts.append(
                f'<path id="{path_id}" class="pipeline-path-dashed" '
                f'd="M {x1} {y} L {x2} {y}" '
                f'stroke="#475569" stroke-width="2" fill="none"/>'
            )
            # Animated particle along the path
            svg_parts.append(
                f'<circle class="pipeline-particle" r="3">'
                f'<animateMotion dur="2s" repeatCount="indefinite">'
                f'<mpath href="#{path_id}"/>'
                f'</animateMotion>'
                f'</circle>'
            )

        # Draw stage nodes
        for idx, (name, subtitle, count, pct, color) in enumerate(stages):
            x = 20 + idx * (node_w + gap)
            y = (svg_h - node_h) // 2
            svg_parts.append(
                f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" '
                f'rx="10" ry="10" fill="rgba(15,23,42,0.6)" '
                f'stroke="{color}" stroke-width="1.5"/>'
            )
            # Stage name
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 22}" text-anchor="middle" '
                f'fill="{color}" font-family="Inter,sans-serif" font-size="11" '
                f'font-weight="700" text-transform="uppercase">{html.escape(name)}</text>'
            )
            # Subtitle
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 36}" text-anchor="middle" '
                f'fill="#64748b" font-family="Inter,sans-serif" font-size="9">'
                f'{html.escape(subtitle)}</text>'
            )
            # Count
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 65}" text-anchor="middle" '
                f'fill="{color}" font-family="Orbitron,monospace" font-size="22" '
                f'font-weight="800">{count}</text>'
            )
            # Percentage
            svg_parts.append(
                f'<text x="{x + node_w // 2}" y="{y + 85}" text-anchor="middle" '
                f'fill="#94a3b8" font-family="Inter,sans-serif" font-size="10">'
                f'{pct} resolved</text>'
            )

        svg_content = "\n".join(svg_parts)

        return f"""
<section class="section-card" id="pipeline">
    <div class="section-header">
        {self._icon('activity', 20, '#38bdf8')}
        <h2>Cascade Pipeline Analysis</h2>
    </div>
    <p class="section-desc">
        Findings are progressively analyzed through three independent stages. Each stage
        either resolves a finding with sufficient confidence or escalates it to the next
        stage for deeper analysis.
    </p>
    <div class="pipeline-svg-container">
        <svg width="{svg_w}" height="{svg_h}" viewBox="0 0 {svg_w} {svg_h}" xmlns="http://www.w3.org/2000/svg">
{svg_content}
        </svg>
    </div>
</section>"""

    def _render_charts(
        self,
        sev_counts: dict[str, int],
        cwe_counts: dict[str, int],
        lang_counts: dict[str, int],
        total: int,
        verdict_counts: dict[str, int] | None = None,
    ) -> str:
        sev_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#3b82f6",
            "info": "#64748b",
        }
        sev_segments = [
            (label.capitalize(), count, sev_colors.get(label, "#64748b"))
            for label, count in sev_counts.items()
            if count > 0
        ]
        sev_donut = self._render_donut_chart(sev_segments, "Severity")

        # Verdict donut chart
        verdict_section = ""
        if verdict_counts:
            verdict_colors = {
                "confirmed": "#ef4444",
                "likely": "#eab308",
                "potential": "#38bdf8",
                "safe": "#22c55e",
            }
            verdict_segments = [
                (label.capitalize(), count, verdict_colors.get(label, "#64748b"))
                for label, count in verdict_counts.items()
                if count > 0
            ]
            verdict_donut = self._render_donut_chart(verdict_segments, "Verdicts")
            verdict_section = f"""
    <div class="chart-card">
        <div class="chart-title">
            {self._icon('shield-check', 16, '#38bdf8')}
            <h3>Verdict Distribution</h3>
        </div>
        {verdict_donut}
    </div>"""

        cwe_chart = self._render_bar_chart(
            dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:8]),
            None,
            total,
        )

        lang_section = ""
        if len(lang_counts) > 1:
            lang_chart = self._render_bar_chart(lang_counts, None, total)
            lang_section = f"""
    <div class="chart-card">
        <div class="chart-title">
            {self._icon('globe', 16, '#38bdf8')}
            <h3>Language Distribution</h3>
        </div>
        <div class="bar-chart">{lang_chart}</div>
    </div>"""

        return f"""
<div class="charts-grid">
    <div class="chart-card">
        <div class="chart-title">
            {self._icon('alert-triangle', 16, '#38bdf8')}
            <h3>Severity Distribution</h3>
        </div>
        {sev_donut}
    </div>{verdict_section}
    <div class="chart-card">
        <div class="chart-title">
            {self._icon('hash', 16, '#38bdf8')}
            <h3>CWE Distribution</h3>
        </div>
        <div class="bar-chart">{cwe_chart}</div>
    </div>{lang_section}
</div>"""

    def _render_findings_section(
        self,
        result: ScanResult,
        total: int,
        confirmed: int,
        likely: int,
        potential: int,
        safe_count: int,
    ) -> str:
        # Stage-wise counts for the primary filter
        sast_n = result.resolved_at_sast
        graph_n = result.resolved_at_graph
        llm_n = result.resolved_at_llm

        return f"""
<section class="section-card" id="findings">
    <div class="section-header">
        {self._icon('file-text', 20, '#38bdf8')}
        <h2>Detailed Findings</h2>
    </div>
    <div class="findings-toolbar">
        <div class="filter-row">
            <div class="filter-group">
                <span class="filter-label">{self._icon('layers', 14, '#94a3b8')} Stage</span>
                <button class="filter-btn stage-btn active" onclick="filterByStage('all',this)">All ({total})</button>
                <button class="filter-btn stage-btn stage-tag-sast" onclick="filterByStage('sast',this)">SAST ({sast_n})</button>
                <button class="filter-btn stage-btn stage-tag-graph" onclick="filterByStage('graph',this)">Graph ({graph_n})</button>
                <button class="filter-btn stage-btn stage-tag-llm" onclick="filterByStage('llm',this)">LLM ({llm_n})</button>
            </div>
            <div class="filter-group">
                <span class="filter-label">{self._icon('filter', 14, '#94a3b8')} Verdict</span>
                <button class="filter-btn verdict-btn active" onclick="filterByVerdict('all',this)">All</button>
                <button class="filter-btn verdict-btn" onclick="filterByVerdict('confirmed',this)">Confirmed ({confirmed})</button>
                <button class="filter-btn verdict-btn" onclick="filterByVerdict('likely',this)">Likely ({likely})</button>
                <button class="filter-btn verdict-btn" onclick="filterByVerdict('potential',this)">Potential ({potential})</button>
                <button class="filter-btn verdict-btn" onclick="filterByVerdict('safe',this)">Safe ({safe_count})</button>
            </div>
        </div>
        <div class="search-box">
            {self._icon('search', 14, '#94a3b8')}
            <input type="text" id="findingSearch" placeholder="Search findings..." oninput="searchFindings(this.value)">
        </div>
    </div>
    <div class="table-wrapper">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th class="sortable" onclick="sortTable(0)">#</th>
                    <th class="sortable" onclick="sortTable(1)">Stage</th>
                    <th class="sortable" onclick="sortTable(2)">Verdict</th>
                    <th class="sortable" onclick="sortTable(3)">Severity</th>
                    <th>CWE</th>
                    <th>Location</th>
                    <th>Description</th>
                    <th class="sortable" onclick="sortTable(7)">Score</th>
                    <th class="sortable" onclick="sortTable(8)">CVSS</th>
                </tr>
            </thead>
            <tbody>
                {self._render_findings_rows(result.findings)}
            </tbody>
        </table>
    </div>
    <div class="table-footer" id="tableFooter">
        Showing {total} of {total} findings
    </div>
</section>"""

    def _render_methodology(self) -> str:
        return f"""
<!-- Floating help button -->
<button class="help-fab" onclick="toggleMethodology()" title="Analysis Methodology" id="helpFab">
    {self._icon('info', 22, '#0f1419')}
</button>

<!-- Methodology slide-out panel -->
<div class="methodology-panel" id="methodologyPanel">
    <div class="methodology-panel-header">
        <h2>Analysis Methodology</h2>
        <button class="modal-close" onclick="toggleMethodology()">
            {self._icon('x-close', 20)}
        </button>
    </div>
    <div class="methodology-panel-body">
        <p class="section-desc">
            Sec-C employs a multi-stage cascade architecture where each finding is progressively
            analyzed through independent detection methods. This section explains each stage and
            how to interpret the results presented in this report.
        </p>

        <div class="methodology-grid">
            <div class="method-card">
                <div class="method-header">
                    <div class="method-icon" style="--method-color:#22c55e">
                        {self._icon('code', 24, '#22c55e')}
                    </div>
                    <div>
                        <h3>Stage 1: Static Application Security Testing (SAST)</h3>
                        <span class="method-tech">CodeQL + Tree-sitter</span>
                    </div>
                </div>
                <div class="method-body">
                    <p>Employs CodeQL semantic analysis and Tree-sitter AST parsing to perform
                    inter-procedural taint analysis across supported languages. Identifies potential
                    vulnerabilities by tracing data flows from untrusted sources to security-sensitive
                    sinks, with pattern matching against known vulnerability signatures.</p>
                    <div class="method-plain">
                        <div class="plain-label">{self._icon('info', 14, '#818cf8')} In Plain Terms</div>
                        <p>This stage reads through your source code without running it, looking for
                        patterns that commonly indicate security vulnerabilities. It traces how data
                        flows through your program &mdash; from user inputs to sensitive operations
                        like database queries or file writes &mdash; to identify places where
                        untrusted data might be used unsafely.</p>
                    </div>
                </div>
            </div>

            <div class="method-card">
                <div class="method-header">
                    <div class="method-icon" style="--method-color:#38bdf8">
                        {self._icon('network', 24, '#38bdf8')}
                    </div>
                    <div>
                        <h3>Stage 2: Graph Neural Network Analysis</h3>
                        <span class="method-tech">Joern CPG + Mini-GAT + TorchCP Conformal Prediction</span>
                    </div>
                </div>
                <div class="method-body">
                    <p>Constructs Code Property Graphs (CPGs) via Joern, capturing control flow,
                    data flow, and program dependence relationships. A Mini-GAT (Graph Attention
                    Network) model processes these graphs to identify complex vulnerability patterns
                    that span multiple functions and files. TorchCP conformal prediction provides
                    calibrated uncertainty estimates with statistical coverage guarantees.</p>
                    <div class="method-plain">
                        <div class="plain-label">{self._icon('info', 14, '#818cf8')} In Plain Terms</div>
                        <p>This stage builds a detailed map of how your code connects &mdash; which
                        functions call which, how data moves between components, and how different
                        parts depend on each other. A specialized AI model analyzes these connections
                        to catch vulnerabilities that simple pattern matching would miss, and assigns
                        a mathematically-grounded confidence score to each finding.</p>
                    </div>
                </div>
            </div>

            <div class="method-card">
                <div class="method-header">
                    <div class="method-icon" style="--method-color:#eab308">
                        {self._icon('cpu', 24, '#eab308')}
                    </div>
                    <div>
                        <h3>Stage 3: LLM-Powered Adversarial Validation</h3>
                        <span class="method-tech">Gemini 2.5 Dual-Agent + NVD RAG</span>
                    </div>
                </div>
                <div class="method-body">
                    <p>Deploys a dual-agent architecture: an attacker agent constructs potential
                    exploitation scenarios while a defender agent evaluates mitigating controls and
                    contextual factors. Findings are cross-referenced against the National
                    Vulnerability Database (NVD) via FAISS/BM25 retrieval-augmented generation to
                    validate against known vulnerability patterns and assess real-world
                    exploitability.</p>
                    <div class="method-plain">
                        <div class="plain-label">{self._icon('info', 14, '#818cf8')} In Plain Terms</div>
                        <p>This stage uses AI to simulate both an attacker trying to exploit the
                        vulnerability and a defender evaluating whether existing protections would
                        prevent the attack. It also checks each finding against a database of known
                        real-world vulnerabilities to assess how likely the issue is to be
                        exploitable in practice.</p>
                    </div>
                </div>
            </div>

            <div class="method-card">
                <div class="method-header">
                    <div class="method-icon" style="--method-color:#818cf8">
                        {self._icon('layers', 24, '#818cf8')}
                    </div>
                    <div>
                        <h3>Cascade Score Fusion &amp; Uncertainty-Driven Escalation</h3>
                        <span class="method-tech">&alpha;&middot;SAST + &beta;&middot;GAT + &gamma;&middot;LLM</span>
                    </div>
                </div>
                <div class="method-body">
                    <p>Final verdicts are computed via weighted score fusion with uncertainty-driven
                    escalation. Findings with high uncertainty at any stage are automatically
                    escalated to deeper analysis rather than prematurely classified, ensuring that
                    ambiguous cases receive the most thorough review. This approach minimizes both
                    false positives and false negatives.</p>
                    <div class="method-plain">
                        <div class="plain-label">{self._icon('info', 14, '#818cf8')} In Plain Terms</div>
                        <p>The framework combines the assessments from all three stages into a single
                        confidence score. When a stage is uncertain about a finding, it passes it
                        forward for deeper analysis rather than guessing &mdash; this means findings
                        classified as &ldquo;Confirmed&rdquo; or &ldquo;Safe&rdquo; have been
                        thoroughly vetted through multiple independent analysis methods.</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="verdict-guide">
            <h3>Understanding Verdicts</h3>
            <div class="verdict-grid">
                <div class="verdict-item">
                    <span class="badge badge-confirmed">Confirmed</span>
                    <p>High-confidence finding validated by multiple analysis stages.
                    Recommended for immediate remediation.</p>
                </div>
                <div class="verdict-item">
                    <span class="badge badge-likely">Likely</span>
                    <p>Strong indicators of vulnerability with moderate confidence.
                    Should be reviewed and prioritized for remediation.</p>
                </div>
                <div class="verdict-item">
                    <span class="badge badge-potential">Potential</span>
                    <p>Possible vulnerability detected with lower confidence.
                    Warrants manual review for confirmation.</p>
                </div>
                <div class="verdict-item">
                    <span class="badge badge-safe">Safe</span>
                    <p>Initially flagged but determined to be a false positive through
                    multi-stage analysis. No action required.</p>
                </div>
            </div>
        </div>
    </div>
</div>
<div class="methodology-backdrop" id="methodologyBackdrop" onclick="toggleMethodology()"></div>"""

    def _render_footer(self, result: ScanResult) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""
<footer class="report-footer">
    <div class="footer-brand">
        <span>Sec-C v2.0.0</span>
    </div>
    <p>Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection</p>
    <p class="footer-meta">Report generated {timestamp}
        &nbsp;&bull;&nbsp; Target: {html.escape(result.scan_target)}</p>
    <p class="footer-disclaimer">This report is generated by automated analysis tools.
    Findings should be validated by qualified security professionals before remediation
    decisions are finalized.</p>
</footer>"""

    def _render_modal(self) -> str:
        return f"""
<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)">
    <div class="modal" onclick="event.stopPropagation()">
        <button class="modal-close" onclick="closeModal()" title="Close (Esc)">
            {self._icon('x-close', 20)}
        </button>
        <div id="modalBody"></div>
    </div>
</div>"""

    # ------------------------------------------------------------------
    # CSS
    # ------------------------------------------------------------------

    def _render_css(self) -> str:
        """Return all CSS rules. Plain string (not f-string) — no brace escaping."""
        return """
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg-body: #0f1419;
    --bg-primary: #151b23;
    --bg-secondary: #1c2333;
    --bg-tertiary: #242d3d;
    --bg-hover: #2a3548;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent: #38bdf8;
    --accent-sec: #818cf8;
    --red: #ef4444;
    --orange: #f97316;
    --yellow: #eab308;
    --blue: #3b82f6;
    --green: #22c55e;
    --purple: #a78bfa;
    --border: #2d3748;
    --border-lt: #374151;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
    --shadow-lg: 0 8px 24px rgba(0,0,0,0.5);
    --radius-sm: 6px;
    --radius-md: 8px;
    --radius-lg: 12px;
}

html { scroll-behavior: smooth; scroll-padding-top: 56px; }
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background-color: #0a0e17;
    background-image: radial-gradient(circle, rgba(56, 189, 248, 0.06) 1px, transparent 1px);
    background-size: 30px 30px;
    animation: gridDrift 60s linear infinite;
    color: var(--text-primary);
    line-height: 1.6;
    font-size: 15px;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}
@keyframes gridDrift {
    0% { background-position: 0 0; }
    100% { background-position: 30px 30px; }
}

/* ---- Scan-line sweep ---- */
body::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #38bdf8, transparent);
    animation: scanLine 2s ease-out forwards;
    z-index: 9999;
    pointer-events: none;
}
@keyframes scanLine {
    0% { top: 0; opacity: 1; }
    100% { top: 100vh; opacity: 0; }
}

/* ---- Accent bar ---- */
.accent-bar {
    height: 3px;
    background: linear-gradient(90deg, #38bdf8, #818cf8, #a78bfa);
}

/* ---- Navigation ---- */
.report-nav {
    position: sticky;
    top: 0;
    z-index: 50;
    background: rgba(15,20,25,0.92);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    padding: 0 32px;
    display: flex;
    align-items: center;
    gap: 32px;
    height: 48px;
}
.nav-brand {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
    color: var(--accent);
    flex-shrink: 0;
}
.nav-brand span {
    font-family: 'Orbitron', sans-serif;
    font-size: 1rem;
    letter-spacing: 2px;
}
.nav-links { display: flex; gap: 4px; flex: 1; }
.nav-links a {
    color: var(--text-secondary);
    text-decoration: none;
    padding: 12px 14px;
    font-size: 0.8rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid transparent;
    transition: color 0.2s, border-color 0.2s;
}
.nav-links a:hover {
    color: var(--text-primary);
    border-bottom-color: var(--accent);
}
.nav-print {
    display: flex;
    align-items: center;
    gap: 6px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    padding: 6px 12px;
    border-radius: var(--radius-sm);
    font-size: 0.8rem;
    cursor: pointer;
    transition: all 0.2s;
    flex-shrink: 0;
}
.nav-print:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
    border-color: var(--border-lt);
}

/* ---- Container ---- */
.container { max-width: 1320px; margin: 0 auto; padding: 28px 32px; }

/* ---- Report header ---- */
.report-header {
    background: var(--bg-primary);
    background-image:
        linear-gradient(rgba(56,189,248,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(56,189,248,0.03) 1px, transparent 1px);
    background-size: 20px 20px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 32px;
    margin-bottom: 24px;
    box-shadow: var(--shadow-md);
}
.header-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 24px;
    margin-bottom: 16px;
}
.header-brand {
    display: flex;
    align-items: flex-start;
    gap: 16px;
}
.header-brand h1 {
    font-family: 'Orbitron', sans-serif;
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: 3px;
    text-transform: uppercase;
    background: linear-gradient(135deg, #38bdf8, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1.2;
    text-shadow: 0 0 30px rgba(56,189,248,0.15);
}
.framework-name {
    font-family: 'Inter', sans-serif;
    font-weight: 300;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-top: 4px;
    line-height: 1.4;
}
.risk-badge {
    text-align: center;
    padding: 12px 24px;
    border-radius: var(--radius-md);
    border: 1px solid var(--risk-color);
    background: rgba(0,0,0,0.2);
    flex-shrink: 0;
    min-width: 120px;
}
.risk-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
    margin-bottom: 4px;
}
.risk-value {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.25rem;
    font-weight: 800;
    color: var(--risk-color);
    letter-spacing: 2px;
}
.risk-narrative {
    color: var(--text-secondary);
    font-size: 0.9rem;
    line-height: 1.6;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
}
.header-meta { display: flex; flex-wrap: wrap; gap: 24px; }
.meta-item {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.825rem;
}
.meta-label { color: var(--text-muted); }
.meta-value { color: var(--text-primary); font-weight: 500; }

/* ---- Metric cards ---- */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
}
.metric-card {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(56, 189, 248, 0.12);
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    padding: 20px;
    text-align: center;
    transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
}
.metric-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
    border-color: rgba(56, 189, 248, 0.3);
}
.metric-icon { margin-bottom: 8px; }
.metric-icon svg { display: inline-block; }
.metric-value {
    font-family: 'Orbitron', sans-serif;
    font-size: 2.25rem;
    font-weight: 800;
    line-height: 1.1;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
}
.metric-label {
    color: var(--text-secondary);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-top: 6px;
}

/* ---- Section cards ---- */
.section-card {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(56, 189, 248, 0.12);
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    padding: 28px;
    margin-bottom: 24px;
}
.section-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
    border-left: 3px solid var(--accent);
    padding-left: 12px;
}
.section-header h2 {
    font-family: 'Inter', sans-serif;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-primary);
}
.section-desc {
    color: var(--text-secondary);
    font-size: 0.875rem;
    line-height: 1.6;
    margin-bottom: 24px;
    max-width: 80ch;
}

/* ---- Pipeline ---- */
.pipeline-flow {
    display: flex;
    align-items: stretch;
}
.pipeline-stage {
    flex: 1;
    text-align: center;
    padding: 24px 16px;
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    transition: border-color 0.2s;
}
.pipeline-stage:hover { border-color: var(--border-lt); }
.stage-icon { margin-bottom: 10px; }
.stage-icon svg { display: inline-block; }
.stage-name {
    font-weight: 700;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 2px;
}
.stage-subtitle {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-bottom: 12px;
}
.stage-count {
    font-family: 'Orbitron', sans-serif;
    font-size: 2rem;
    font-weight: 800;
    line-height: 1.1;
}
.stage-pct { font-size: 0.775rem; color: var(--text-secondary); margin-top: 4px; }

.stage-sast .stage-name, .stage-sast .stage-count { color: var(--green); }
.stage-graph .stage-name, .stage-graph .stage-count { color: var(--accent); }
.stage-llm .stage-name, .stage-llm .stage-count { color: var(--yellow); }
.stage-unresolved .stage-name, .stage-unresolved .stage-count { color: var(--red); }

.pipeline-connector {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    flex-shrink: 0;
    position: relative;
}
.connector-line {
    position: absolute;
    top: 50%;
    left: 0; right: 0;
    height: 1px;
    background: var(--border-lt);
}
.pipeline-connector svg {
    position: relative;
    z-index: 1;
    background: var(--bg-body);
    padding: 2px;
}

/* ---- Charts ---- */
.charts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.chart-card {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(56, 189, 248, 0.12);
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    padding: 22px;
}
.chart-title {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 18px;
}
.chart-title h3 {
    font-family: 'Inter', sans-serif;
    font-size: 0.825rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
}

.bar-chart { display: flex; flex-direction: column; gap: 8px; }
.bar-row { display: flex; align-items: center; gap: 10px; }
.bar-label {
    width: 140px;
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-align: right;
    flex-shrink: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.bar-container {
    flex: 1;
    height: 26px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    overflow: hidden;
}
.bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.6s ease;
    display: flex;
    align-items: center;
    padding-left: 10px;
    font-size: 0.75rem;
    font-weight: 600;
    color: rgba(255,255,255,0.9);
    min-width: fit-content;
}
.bar-count {
    width: 36px;
    text-align: right;
    font-size: 0.8rem;
    color: var(--text-secondary);
    font-weight: 600;
    flex-shrink: 0;
}

/* ---- Findings table ---- */
.findings-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 18px;
    flex-wrap: wrap;
}
.filter-group {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
}
.filter-btn {
    padding: 5px 13px;
    border: 1px solid var(--border);
    border-radius: 20px;
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 0.8rem;
    font-weight: 500;
    transition: all 0.2s;
}
.filter-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
}
.filter-btn.active {
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(56,189,248,0.08);
}
.search-box {
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 6px 12px;
    transition: border-color 0.2s;
}
.search-box:focus-within { border-color: var(--accent); }
.search-box input {
    background: transparent;
    border: none;
    color: var(--text-primary);
    font-size: 0.825rem;
    outline: none;
    width: 180px;
}
.search-box input::placeholder { color: var(--text-muted); }

.table-wrapper {
    overflow-x: auto;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
}
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
thead { background: var(--bg-secondary); }
th {
    text-align: left;
    padding: 10px 14px;
    color: var(--text-muted);
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    user-select: none;
}
th.sortable { cursor: pointer; }
th.sortable:hover { color: var(--text-secondary); }
th.sortable::after {
    content: '';
    display: inline-block;
    margin-left: 4px;
    opacity: 0.3;
    font-size: 0.65rem;
}
th.sort-asc::after { content: '\\25B2'; opacity: 1; }
th.sort-desc::after { content: '\\25BC'; opacity: 1; }

td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
}
tbody tr {
    cursor: pointer;
    transition: background 0.15s;
}
tbody tr:hover { background: var(--bg-hover); }
tbody tr:last-child td { border-bottom: none; }

.table-footer {
    padding: 10px 14px;
    font-size: 0.775rem;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
}

/* ---- Badges ---- */
.badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 10px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    white-space: nowrap;
}
.badge-critical { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-high { background: rgba(249,115,22,0.15); color: var(--orange); }
.badge-medium { background: rgba(234,179,8,0.15); color: var(--yellow); }
.badge-low { background: rgba(59,130,246,0.15); color: var(--blue); }
.badge-info { background: rgba(100,116,139,0.15); color: var(--text-muted); }
.badge-confirmed { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-likely { background: rgba(234,179,8,0.15); color: var(--yellow); }
.badge-potential { background: rgba(56,189,248,0.15); color: var(--accent); }
.badge-safe { background: rgba(34,197,94,0.15); color: var(--green); }

.badge-cvss-critical { background: rgba(239,68,68,0.15); color: var(--red); font-family: 'Orbitron', sans-serif; animation: pulseCritical 2s ease-in-out infinite; }
.badge-critical { animation: pulseCritical 2s ease-in-out infinite; }
@keyframes pulseCritical {
    0%, 100% { box-shadow: 0 0 4px rgba(239, 68, 68, 0.4); }
    50% { box-shadow: 0 0 16px rgba(239, 68, 68, 0.8); }
}
.badge-cvss-high { background: rgba(249,115,22,0.15); color: var(--orange); font-family: 'Orbitron', sans-serif; }
.badge-cvss-medium { background: rgba(234,179,8,0.15); color: var(--yellow); font-family: 'Orbitron', sans-serif; }
.badge-cvss-low { background: rgba(59,130,246,0.15); color: var(--blue); font-family: 'Orbitron', sans-serif; }
.badge-cvss-none { background: rgba(100,116,139,0.15); color: var(--text-muted); }

/* Stage tag badges */
.stage-tag-sast { background: rgba(34,197,94,0.15); color: var(--green); }
.stage-tag-graph { background: rgba(56,189,248,0.15); color: var(--accent); }
.stage-tag-llm { background: rgba(234,179,8,0.15); color: var(--yellow); }
.stage-tag-unresolved { background: rgba(239,68,68,0.15); color: var(--red); }

/* Dual filter layout */
.filter-row {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.filter-label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-right: 4px;
    flex-shrink: 0;
}

/* ---- Methodology ---- */
.methodology-grid { display: grid; gap: 18px; margin-bottom: 28px; }
.method-card {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(56, 189, 248, 0.12);
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    overflow: hidden;
}
.method-header {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 22px;
    border-bottom: 1px solid var(--border);
}
.method-icon {
    padding: 10px;
    background: rgba(0,0,0,0.2);
    border-radius: var(--radius-sm);
    flex-shrink: 0;
    border: 1px solid var(--method-color);
}
.method-header h3 {
    font-family: 'Inter', sans-serif;
    font-size: 0.925rem;
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1.3;
}
.method-tech {
    display: inline-block;
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 3px;
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
}
.method-body { padding: 18px 22px; }
.method-body > p {
    color: var(--text-secondary);
    font-size: 0.85rem;
    line-height: 1.65;
    margin-bottom: 14px;
}
.method-plain {
    background: var(--bg-tertiary);
    border-radius: var(--radius-sm);
    padding: 14px 16px;
    border-left: 3px solid var(--accent-sec);
}
.plain-label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--accent-sec);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
}
.method-plain p {
    color: var(--text-secondary);
    font-size: 0.84rem;
    line-height: 1.6;
}

/* ---- Verdict guide ---- */
.verdict-guide {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 22px;
}
.verdict-guide h3 {
    font-family: 'Inter', sans-serif;
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 16px;
}
.verdict-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 14px;
}
.verdict-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px;
    background: var(--bg-tertiary);
    border-radius: var(--radius-sm);
}
.verdict-item .badge { flex-shrink: 0; margin-top: 2px; }
.verdict-item p {
    color: var(--text-secondary);
    font-size: 0.825rem;
    line-height: 1.5;
}

/* ---- Modal ---- */
.modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.65);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    z-index: 100;
    justify-content: center;
    align-items: flex-start;
    padding-top: 4vh;
    overflow-y: auto;
}
.modal-overlay.active { display: flex; }
.modal {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    width: 92%;
    max-width: 920px;
    max-height: 88vh;
    overflow-y: auto;
    padding: 28px;
    box-shadow: var(--shadow-lg);
    position: relative;
    margin-bottom: 4vh;
}
.modal-close {
    position: absolute;
    top: 16px; right: 16px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    cursor: pointer;
    padding: 6px;
    display: flex;
    transition: all 0.2s;
}
.modal-close:hover {
    color: var(--text-primary);
    border-color: var(--border-lt);
}
.modal-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 20px;
    padding-right: 40px;
}
.detail-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}
.detail-item {
    padding: 14px;
    background: var(--bg-secondary);
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
}
.detail-item .label {
    color: var(--text-muted);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 600;
}
.detail-item .value { font-size: 1rem; margin-top: 6px; font-weight: 500; }
.modal-section-title {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin: 20px 0 10px;
}
.modal pre {
    background: var(--bg-body);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 16px;
    overflow-x: auto;
    font-size: 0.82rem;
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
    line-height: 1.6;
    color: var(--text-primary);
}
.modal .explanation {
    background: var(--bg-secondary);
    border-left: 3px solid var(--accent);
    padding: 16px;
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    white-space: pre-wrap;
    font-size: 0.85rem;
    line-height: 1.6;
    color: var(--text-secondary);
}

/* ---- Floating help button ---- */
.help-fab {
    position: fixed;
    bottom: 32px;
    right: 32px;
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: var(--accent);
    border: none;
    color: #0f1419;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 16px rgba(56,189,248,0.3);
    transition: all 0.3s;
    z-index: 60;
}
.help-fab:hover {
    transform: scale(1.1);
    box-shadow: 0 6px 24px rgba(56,189,248,0.5);
}

/* ---- Methodology panel ---- */
.methodology-panel {
    position: fixed;
    top: 0;
    right: -520px;
    width: 500px;
    max-width: 90vw;
    height: 100vh;
    background: var(--bg-primary);
    border-left: 1px solid var(--border);
    z-index: 200;
    overflow-y: auto;
    transition: right 0.35s ease;
    box-shadow: -8px 0 32px rgba(0,0,0,0.5);
}
.methodology-panel.active {
    right: 0;
}
.methodology-panel-header {
    position: sticky;
    top: 0;
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border);
    padding: 20px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    z-index: 1;
}
.methodology-panel-header h2 {
    font-family: 'Inter', sans-serif;
    font-size: 1rem;
    font-weight: 600;
}
.methodology-panel-header .modal-close {
    position: static;
}
.methodology-panel-body {
    padding: 24px;
}
.methodology-backdrop {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.5);
    z-index: 190;
}
.methodology-backdrop.active {
    display: block;
}

/* ---- Footer ---- */
.report-footer {
    text-align: center;
    padding: 32px 24px;
    color: var(--text-muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    margin-top: 8px;
}
.footer-brand {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 6px;
}
.footer-brand span {
    font-family: 'Orbitron', sans-serif;
}
.report-footer p { margin-top: 4px; line-height: 1.5; }
.footer-meta { margin-top: 8px !important; }
.footer-disclaimer {
    margin-top: 12px !important;
    font-style: italic;
    max-width: 60ch;
    margin-left: auto;
    margin-right: auto;
}

/* ---- Donut chart ---- */
.donut-chart { position: relative; display: inline-block; }
.donut-chart svg { transform: rotate(-90deg); }
.donut-segment {
    fill: none;
    stroke-width: 8;
    stroke-linecap: round;
    transition: stroke-dashoffset 1s ease-out;
}
.donut-center {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}
.donut-center .donut-total { font-family: 'Orbitron', monospace; font-size: 1.5rem; color: #e2e8f0; }
.donut-center .donut-label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; }
.donut-legend { display: flex; flex-wrap: wrap; gap: 8px 16px; margin-top: 12px; justify-content: center; }
.donut-legend-item { display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: #94a3b8; }
.donut-legend-dot { width: 8px; height: 8px; border-radius: 50%; }

/* ---- Risk gauge ---- */
.risk-gauge { position: relative; width: 180px; height: 100px; margin: 0 auto; }
.risk-gauge svg { overflow: visible; }
.gauge-track { fill: none; stroke: #1e293b; stroke-width: 12; stroke-linecap: round; }
.gauge-fill { fill: none; stroke-width: 12; stroke-linecap: round; transition: stroke-dashoffset 1.5s ease-out; }
.gauge-needle { transform-origin: 50% 100%; transition: transform 1.5s ease-out; }
.gauge-value { font-family: 'Orbitron', monospace; font-size: 1.4rem; fill: #e2e8f0; text-anchor: middle; }
.gauge-label { font-size: 0.7rem; fill: #94a3b8; text-anchor: middle; text-transform: uppercase; }

/* ---- Scan timeline ---- */
.scan-timeline { display: flex; align-items: center; gap: 0; margin: 16px 0; border-radius: 8px; overflow: hidden; height: 36px; }
.timeline-stage { height: 100%; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: 600; color: #0f1419; position: relative; cursor: pointer; transition: opacity 0.2s; min-width: 60px; }
.timeline-stage:hover { opacity: 0.85; }
.timeline-stage .timeline-label { z-index: 1; }
.timeline-total { font-size: 0.75rem; color: #64748b; margin-top: 6px; text-align: right; }

/* ---- Expandable finding rows ---- */
.finding-expand-btn {
    background: none; border: none; cursor: pointer; color: #64748b; padding: 2px 6px;
    transition: transform 0.3s ease, color 0.3s ease;
}
.finding-expand-btn.expanded { transform: rotate(90deg); color: #38bdf8; }
.finding-detail-row { display: none; }
.finding-detail-row.expanded { display: table-row; }
.finding-detail-row td {
    padding: 16px 24px;
    background: rgba(15, 23, 42, 0.4);
    border-bottom: 1px solid #2d3748;
}
.finding-detail-content {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;
}
.finding-detail-content pre {
    background: #0a0e17; border-radius: 8px; padding: 12px; overflow-x: auto;
    font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.5;
    border: 1px solid #2d3748;
}
/* Syntax highlighting */
.hl-keyword { color: #c084fc; font-weight: bold; }
.hl-string { color: #4ade80; }
.hl-comment { color: #64748b; font-style: italic; }
.hl-number { color: #38bdf8; }
.hl-function { color: #fbbf24; }

/* ---- Animated pipeline SVG ---- */
.pipeline-svg-container { width: 100%; overflow-x: auto; }
.pipeline-svg-container svg { display: block; margin: 0 auto; }
.pipeline-node rect { rx: 10; ry: 10; }
.pipeline-path-dashed {
    stroke-dasharray: 8 4;
    animation: dashFlow 1.5s linear infinite;
}
@keyframes dashFlow {
    0% { stroke-dashoffset: 24; }
    100% { stroke-dashoffset: 0; }
}
.pipeline-particle {
    fill: var(--accent);
    opacity: 0.8;
}

/* ---- Animations ---- */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}
.report-header, .metrics-grid, .section-card, .charts-grid {
    animation: fadeIn 0.4s ease-out;
}

/* ---- Reduced motion accessibility ---- */
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
    body::after { display: none; }
    .donut-segment { transition: none; }
    .gauge-fill { transition: none; }
    .gauge-needle { transition: none; }
    .metric-card { transition: none; }
    .pipeline-path-dashed { animation: none; }
}

/* ---- Responsive ---- */
@media (max-width: 768px) {
    .container { padding: 16px; }
    .report-nav { padding: 0 16px; gap: 16px; }
    .nav-print span { display: none; }
    .header-top { flex-direction: column; }
    .pipeline-flow { flex-direction: column; }
    .pipeline-connector {
        width: auto; height: 32px;
        justify-content: center;
    }
    .connector-line {
        top: 0; bottom: 0; left: 50%;
        width: 1px; height: auto; right: auto;
    }
    .charts-grid { grid-template-columns: 1fr; }
    .findings-toolbar { flex-direction: column; align-items: stretch; }
    .search-box input { width: 100%; }
    .detail-grid { grid-template-columns: 1fr; }
}

/* ---- Print ---- */
@media print {
    :root {
        --bg-body: #ffffff;
        --bg-primary: #ffffff;
        --bg-secondary: #f8f9fa;
        --bg-tertiary: #f1f3f5;
        --bg-hover: #e9ecef;
        --text-primary: #1a1a1a;
        --text-secondary: #555555;
        --text-muted: #777777;
        --border: #dddddd;
        --border-lt: #cccccc;
    }

    @page {
        size: A4;
        margin: 18mm 15mm 18mm 15mm;
    }

    body { font-size: 10pt; }

    /* Hide interactive elements */
    .help-fab, .methodology-panel, .methodology-backdrop { display: none !important; }
    .accent-bar, .report-nav { display: none !important; }
    body::after { display: none !important; }
    body { animation: none !important; background-image: none !important; background-color: #fff !important; }
    .filter-group, .search-box, .findings-toolbar { display: none; }
    .modal-overlay { display: none !important; }

    .container { max-width: 100%; padding: 0; }
    .report-header, .section-card, .chart-card, .metric-card,
    .method-card, .verdict-item {
        box-shadow: none;
        break-inside: avoid;
    }

    /* Proper page breaks */
    .report-header { page-break-after: avoid; }
    .metrics-grid { page-break-inside: avoid; }
    .section-card { page-break-inside: avoid; page-break-before: auto; }
    .chart-card { page-break-inside: avoid; }
    .pipeline-flow { page-break-inside: avoid; }

    /* Better table for PDF */
    table { font-size: 8pt; }
    th { background: #f0f0f0 !important; color: #333 !important; }
    td { padding: 6px 8px; }

    .bar-fill, .badge, .risk-badge {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }
    a { color: inherit; text-decoration: none; }

    /* Footer on each page */
    .report-footer {
        position: fixed;
        bottom: 0;
        width: 100%;
        font-size: 7pt;
        padding: 8px 0;
        border-top: 1px solid #ccc;
    }

    .footer-disclaimer { color: #999; }

    /* Ensure print fonts work */
    .header-brand h1, .nav-brand span, .risk-value, .metric-value, .stage-count {
        -webkit-text-fill-color: initial !important;
        background: none !important;
        color: #1a1a1a !important;
        font-family: 'Orbitron', Arial, sans-serif;
    }

    /* Pipeline stage colors for print */
    .stage-sast .stage-count { color: #16a34a !important; }
    .stage-graph .stage-count { color: #0284c7 !important; }
    .stage-llm .stage-count { color: #ca8a04 !important; }
    .stage-unresolved .stage-count { color: #dc2626 !important; }
}
"""

    # ------------------------------------------------------------------
    # JavaScript
    # ------------------------------------------------------------------

    def _render_javascript(self, findings_json: str) -> str:
        """Return all client-side JS. Uses string concat to avoid brace escaping."""
        return "const findings = " + findings_json + ";\n" + """
/* ---- Animated counters ---- */
function animateCounters() {
    document.querySelectorAll('.metric-value[data-target]').forEach(function(el, i) {
        var target = parseInt(el.getAttribute('data-target'));
        var suffix = el.getAttribute('data-suffix') || '';
        var duration = 1500;
        var start = performance.now();
        setTimeout(function() {
            function step(now) {
                var elapsed = now - start;
                var progress = Math.min(elapsed / duration, 1);
                var eased = 1 - Math.pow(1 - progress, 3);
                el.textContent = Math.round(target * eased) + suffix;
                if (progress < 1) requestAnimationFrame(step);
            }
            start = performance.now();
            requestAnimationFrame(step);
        }, i * 100);
    });
}

/* ---- Donut chart animation ---- */
function animateDonuts() {
    document.querySelectorAll('.donut-segment').forEach(function(seg, i) {
        var len = parseFloat(seg.getAttribute('data-length'));
        seg.style.strokeDasharray = len + ' ' + (2 * Math.PI * 60);
        seg.style.strokeDashoffset = len;
        setTimeout(function() {
            seg.style.strokeDashoffset = '0';
        }, 300 + i * 200);
    });
}

/* ---- Syntax highlighter ---- */
function highlightCode(code) {
    return code
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/(#.*$|\\/\\/.*$)/gm, '<span class="hl-comment">$1</span>')
        .replace(/("(?:[^"\\\\\\\\]|\\\\\\\\.)*"|'(?:[^'\\\\\\\\]|\\\\\\\\.)*')/g, '<span class="hl-string">$1</span>')
        .replace(/\\b(\\d+\\.?\\d*)\\b/g, '<span class="hl-number">$1</span>')
        .replace(/\\b(def|class|import|from|return|if|elif|else|for|while|try|except|with|as|in|not|and|or|True|False|None|var|let|const|function|public|private|static|void|int|String|boolean)\\b/g, '<span class="hl-keyword">$1</span>');
}

/* ---- Expandable finding rows ---- */
function toggleFinding(index) {
    var btn = document.querySelector('.expand-btn-' + index);
    var row = document.getElementById('detail-row-' + index);
    if (row) {
        var isExpanded = row.classList.contains('expanded');
        row.classList.toggle('expanded');
        btn.classList.toggle('expanded');
        if (!isExpanded && row.querySelector('pre:not(.highlighted)')) {
            var pre = row.querySelector('pre');
            pre.innerHTML = highlightCode(pre.textContent);
            pre.classList.add('highlighted');
        }
    }
}

var currentStage = 'all';
var currentVerdict = 'all';
var currentSearch = '';

function filterByStage(stage, btn) {
    currentStage = stage;
    applyFilters();
    var buttons = document.querySelectorAll('.stage-btn');
    for (var i = 0; i < buttons.length; i++) buttons[i].classList.remove('active');
    if (btn) btn.classList.add('active');
}

function filterByVerdict(verdict, btn) {
    currentVerdict = verdict;
    applyFilters();
    var buttons = document.querySelectorAll('.verdict-btn');
    for (var i = 0; i < buttons.length; i++) buttons[i].classList.remove('active');
    if (btn) btn.classList.add('active');
}

function searchFindings(query) {
    currentSearch = query.toLowerCase();
    applyFilters();
}

function applyFilters() {
    var rows = document.querySelectorAll('#findingsTable tbody tr');
    var visible = 0;
    var total = 0;
    for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        if (row.classList.contains('finding-detail-row')) continue;
        total++;
        var matchStage = currentStage === 'all' || row.dataset.stage === currentStage;
        var matchVerdict = currentVerdict === 'all' || row.dataset.verdict === currentVerdict;
        var text = row.textContent.toLowerCase();
        var matchSearch = !currentSearch || text.indexOf(currentSearch) !== -1;
        if (matchStage && matchVerdict && matchSearch) {
            row.style.display = '';
            visible++;
        } else {
            row.style.display = 'none';
            var detailRow = document.getElementById('detail-row-' + row.dataset.findingIndex);
            if (detailRow) { detailRow.classList.remove('expanded'); }
        }
    }
    var footer = document.getElementById('tableFooter');
    if (footer) footer.textContent = 'Showing ' + visible + ' of ' + total + ' findings';
}

var sortCol = -1;
var sortAsc = true;

function sortTable(colIndex) {
    var table = document.getElementById('findingsTable');
    var tbody = table.querySelector('tbody');
    var allRows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    var headers = table.querySelectorAll('th');
    var dataRows = allRows.filter(function(r) { return !r.classList.contains('finding-detail-row'); });

    if (sortCol === colIndex) {
        sortAsc = !sortAsc;
    } else {
        sortCol = colIndex;
        sortAsc = true;
    }

    for (var i = 0; i < headers.length; i++) {
        headers[i].classList.remove('sort-asc', 'sort-desc');
    }
    headers[colIndex].classList.add(sortAsc ? 'sort-asc' : 'sort-desc');

    dataRows.sort(function(a, b) {
        var aSort = a.cells[colIndex].dataset.sort;
        var bSort = b.cells[colIndex].dataset.sort;
        var aVal, bVal, cmp;
        if (aSort !== undefined && aSort !== '') {
            aVal = parseFloat(aSort);
            bVal = parseFloat(bSort);
        } else {
            var aText = a.cells[colIndex].textContent.trim();
            var bText = b.cells[colIndex].textContent.trim();
            aVal = parseFloat(aText);
            bVal = parseFloat(bText);
            if (isNaN(aVal) || isNaN(bVal)) {
                cmp = aText.localeCompare(bText);
                return sortAsc ? cmp : -cmp;
            }
        }
        cmp = aVal - bVal;
        return sortAsc ? cmp : -cmp;
    });

    for (var j = 0; j < dataRows.length; j++) {
        tbody.appendChild(dataRows[j]);
        var detailId = 'detail-row-' + dataRows[j].dataset.findingIndex;
        var detail = document.getElementById(detailId);
        if (detail) tbody.appendChild(detail);
    }
}

function showFinding(index) {
    var f = findings[index];
    var modal = document.getElementById('modalOverlay');
    var body = document.getElementById('modalBody');

    var h = '<div class="modal-title">' + f.cwe_id + ' \\u2014 ' + (f.cwe_name || f.rule_id) + '</div>';
    h += '<div class="detail-grid">';
    h += '<div class="detail-item"><div class="label">Verdict</div><div class="value"><span class="badge badge-' + f.verdict + '">' + f.verdict + '</span></div></div>';
    h += '<div class="detail-item"><div class="label">Severity</div><div class="value"><span class="badge badge-' + f.severity + '">' + f.severity + '</span></div></div>';
    h += '<div class="detail-item"><div class="label">Fused Score</div><div class="value">' + (f.fused_score * 100).toFixed(1) + '%</div></div>';
    h += '<div class="detail-item"><div class="label">Stage Resolved</div><div class="value">' + f.stage_resolved + '</div></div>';
    h += '<div class="detail-item"><div class="label">Location</div><div class="value" style="font-family:monospace;font-size:0.85rem">' + f.location + '</div></div>';
    h += '<div class="detail-item"><div class="label">SAST Confidence</div><div class="value">' + (f.sast_confidence * 100).toFixed(0) + '%</div></div>';
    h += '<div class="detail-item"><div class="label">CVSS v3.1</div><div class="value"><span class="badge badge-cvss-' + f.cvss_severity + '">' + f.cvss_base_score.toFixed(1) + '</span> ' + f.cvss_severity.toUpperCase() + '</div></div>';
    h += '<div class="detail-item"><div class="label">CVSS Vector</div><div class="value" style="font-family:monospace;font-size:0.8rem">' + (f.cvss_vector || 'N/A') + '</div></div>';
    h += '</div>';

    h += '<div class="modal-section-title">Description</div>';
    h += '<p style="color:var(--text-secondary);font-size:0.875rem;line-height:1.6">' + f.message + '</p>';

    if (f.snippet) {
        h += '<div class="modal-section-title">Source Code</div>';
        h += '<pre>' + f.snippet + '</pre>';
    }

    if (f.evidence_narrative) {
        h += '<div class="modal-section-title">Assessment Summary</div>';
        h += '<div class="explanation" style="border-left-color:var(--yellow)">' + f.evidence_narrative + '</div>';
    }

    if (f.explanation) {
        h += '<div class="modal-section-title">Analysis</div>';
        h += '<div class="explanation">' + f.explanation + '</div>';
    }

    body.innerHTML = h;
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal(event) {
    var overlay = document.getElementById('modalOverlay');
    if (!event || event.target === overlay) {
        overlay.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function toggleMethodology() {
    var panel = document.getElementById('methodologyPanel');
    var backdrop = document.getElementById('methodologyBackdrop');
    var fab = document.getElementById('helpFab');
    panel.classList.toggle('active');
    backdrop.classList.toggle('active');
    if (panel.classList.contains('active')) {
        document.body.style.overflow = 'hidden';
    } else {
        document.body.style.overflow = '';
    }
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
        var panel = document.getElementById('methodologyPanel');
        if (panel && panel.classList.contains('active')) {
            toggleMethodology();
        }
    }
});

// Smooth scroll for nav links
var navLinks = document.querySelectorAll('.nav-links a');
for (var i = 0; i < navLinks.length; i++) {
    navLinks[i].addEventListener('click', function(e) {
        e.preventDefault();
        var target = document.querySelector(this.getAttribute('href'));
        if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
}

// Trigger animations on page load
document.addEventListener('DOMContentLoaded', function() {
    animateCounters();
    animateDonuts();
});
"""

    # ------------------------------------------------------------------
    # Data helpers
    # ------------------------------------------------------------------

    def _finding_to_dict(self, f: Finding) -> dict[str, Any]:
        """Convert a Finding to a JSON-serializable dict for the frontend."""
        return {
            "id": f.id,
            "rule_id": f.rule_id,
            "cwe_id": f.cwe_id,
            "cwe_name": f.cwe_name,
            "severity": f.severity.value,
            "verdict": f.verdict.value,
            "location": f.location.display,
            "message": f.sast_message,
            "snippet": html.escape(f.location.snippet or ""),
            "fused_score": round(f.fused_score, 4),
            "sast_confidence": round(f.sast_confidence, 4),
            "stage_resolved": f.stage_resolved.value,
            "explanation": html.escape(f.nl_explanation or ""),
            "language": f.language.value,
            "cvss_base_score": round(f.cvss_base_score, 1),
            "cvss_vector": f.cvss_vector,
            "cvss_severity": f.cvss_severity,
            "evidence_narrative": f.llm_validation.evidence_narrative if f.llm_validation else "",
        }

    STAGE_SORT: dict[str, int] = {
        "sast": 1, "graph": 2, "llm": 3, "unresolved": 4,
    }

    def _render_findings_rows(self, findings: list[Finding]) -> str:
        """Render HTML table rows for findings with expandable detail rows."""
        mono = "'JetBrains Mono','SF Mono','Fira Code','Cascadia Code',Consolas,monospace"
        rows = []
        for i, f in enumerate(findings):
            sev_class = f"badge-{f.severity.value}"
            verdict_class = f"badge-{f.verdict.value}"
            stage = f.stage_resolved.value
            stage_class = f"stage-tag-{stage}"
            v_sort = self.VERDICT_SORT.get(f.verdict.value, 0)
            s_sort = self.SEVERITY_SORT.get(f.severity.value, 0)
            st_sort = self.STAGE_SORT.get(stage, 9)
            snippet = html.escape(f.location.snippet or "No source available")
            explanation = html.escape(f.nl_explanation or "")
            row = (
                f'<tr data-verdict="{f.verdict.value}" data-stage="{stage}" '
                f'data-finding-index="{i}" onclick="showFinding({i})">'
                f'<td style="color:var(--text-muted)">'
                f'<button class="finding-expand-btn expand-btn-{i}" '
                f'onclick="event.stopPropagation();toggleFinding({i})" title="Expand">'
                f'{self._icon("chevron-right", 14)}'
                f'</button>'
                f' {i + 1}</td>'
                f'<td data-sort="{st_sort}"><span class="badge {stage_class}">{stage.upper()}</span></td>'
                f'<td data-sort="{v_sort}"><span class="badge {verdict_class}">{f.verdict.value}</span></td>'
                f'<td data-sort="{s_sort}"><span class="badge {sev_class}">{f.severity.value}</span></td>'
                f'<td style="font-family:{mono};font-size:0.8rem">{html.escape(f.cwe_id)}</td>'
                f'<td style="font-family:{mono};font-size:0.8rem">{html.escape(f.location.display)}</td>'
                f"<td>{html.escape(f.sast_message[:80])}</td>"
                f'<td style="font-family:{mono}">{f.fused_score:.2f}</td>'
                f'<td><span class="badge badge-cvss-{f.cvss_severity}">{f.cvss_base_score:.1f}</span></td>'
                f"</tr>"
            )
            detail_row = (
                f'<tr class="finding-detail-row" id="detail-row-{i}">'
                f'<td colspan="9">'
                f'<div class="finding-detail-content">'
                f'<div>'
                f'<div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;'
                f'letter-spacing:0.5px;margin-bottom:6px">Source Code</div>'
                f'<pre>{snippet}</pre>'
                f'</div>'
                f'<div>'
                f'<div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;'
                f'letter-spacing:0.5px;margin-bottom:6px">Details</div>'
                f'<div style="font-size:0.825rem;color:var(--text-secondary);line-height:1.5">'
                f'<strong>SAST Confidence:</strong> {f.sast_confidence:.0%}<br>'
                f'<strong>Fused Score:</strong> {f.fused_score:.2f}<br>'
                f'<strong>CVSS:</strong> {f.cvss_base_score:.1f} ({f.cvss_severity})'
                f'</div>'
                + (f'<div style="margin-top:8px;font-size:0.825rem;'
                   f'color:var(--text-secondary);'
                   f'line-height:1.5">{explanation}</div>'
                   if explanation else '')
                + '</div>'
                '</div>'
                '</td>'
                '</tr>'
            )
            rows.append(row)
            rows.append(detail_row)
        return "\n".join(rows)

    def _render_donut_chart(
        self,
        segments: list[tuple[str, int, str]],
        title: str,
    ) -> str:
        """Render an SVG donut chart.

        Args:
            segments: list of (label, count, color) tuples.
            title: Chart center label.
        """
        total = sum(count for _, count, _ in segments)
        if total == 0:
            return '<div style="color:var(--text-muted);font-size:0.85rem">No data available</div>'

        radius = 60
        circumference = 2 * 3.14159265 * radius
        offset = 0
        svg_segments = []

        for label, count, color in segments:
            if count == 0:
                continue
            length = (count / total) * circumference
            svg_segments.append(
                f'<circle class="donut-segment" cx="75" cy="75" r="{radius}" '
                f'stroke="{color}" '
                f'stroke-dasharray="0 {circumference:.2f}" '
                f'stroke-dashoffset="-{offset:.2f}" '
                f'data-length="{length:.2f}"/>'
            )
            offset += length

        legend_items = []
        for label, count, color in segments:
            if count == 0:
                continue
            legend_items.append(
                f'<span class="donut-legend-item">'
                f'<span class="donut-legend-dot" style="background:{color}"></span>'
                f'{html.escape(label)} ({count})'
                f'</span>'
            )

        return (
            f'<div style="text-align:center">'
            f'<div class="donut-chart">'
            f'<svg width="150" height="150" viewBox="0 0 150 150">'
            f'{"".join(svg_segments)}'
            f'</svg>'
            f'<div class="donut-center">'
            f'<div class="donut-total">{total}</div>'
            f'<div class="donut-label">{html.escape(title)}</div>'
            f'</div>'
            f'</div>'
            f'<div class="donut-legend">{"".join(legend_items)}</div>'
            f'</div>'
        )

    def _render_risk_gauge(
        self,
        risk_level: str,
        risk_color: str,
        score: float | None = None,
    ) -> str:
        """Render a semi-circular SVG gauge for the risk score."""
        level_scores = {
            "CRITICAL": 0.95,
            "HIGH": 0.75,
            "MEDIUM": 0.50,
            "LOW": 0.25,
            "MINIMAL": 0.05,
        }
        value = score if score is not None else level_scores.get(risk_level, 0.5)

        # Arc: semi-circle from left to right
        # Path goes from (10,90) to (170,90) via the top
        arc_length = 3.14159265 * 80  # half circumference, r=80
        fill_length = value * arc_length
        remaining = arc_length - fill_length

        # Needle rotation: -90 (left) to +90 (right)
        needle_deg = -90 + (value * 180)

        return (
            f'<div class="risk-gauge">'
            f'<svg width="180" height="110" viewBox="0 0 180 110">'
            # Track
            f'<path class="gauge-track" d="M 10 95 A 80 80 0 0 1 170 95"/>'
            # Fill
            f'<path class="gauge-fill" d="M 10 95 A 80 80 0 0 1 170 95" '
            f'stroke="{risk_color}" '
            f'stroke-dasharray="{arc_length:.1f}" '
            f'stroke-dashoffset="{remaining:.1f}"/>'
            # Needle
            f'<g class="gauge-needle" style="transform:rotate({needle_deg:.0f}deg)">'
            f'<line x1="90" y1="95" x2="90" y2="25" stroke="{risk_color}" stroke-width="2"/>'
            f'<circle cx="90" cy="95" r="4" fill="{risk_color}"/>'
            f'</g>'
            # Labels
            f'<text class="gauge-value" x="90" y="85">{html.escape(risk_level)}</text>'
            f'<text class="gauge-label" x="90" y="108">Risk Level</text>'
            f'</svg>'
            f'</div>'
        )

    def _render_timeline(self, result: ScanResult) -> str:
        """Render the scan timeline waterfall showing stage durations."""
        total_ms = result.scan_duration_ms
        if total_ms <= 0:
            return ""

        # Build stage timing data from available info
        stage_data = [
            ("SAST", result.resolved_at_sast, "#22c55e"),
            ("Graph", result.resolved_at_graph, "#38bdf8"),
            ("LLM", result.resolved_at_llm, "#eab308"),
        ]

        total_resolved = sum(s[1] for s in stage_data)
        if total_resolved == 0:
            return ""

        # Approximate time proportional to findings resolved
        segments = []
        for name, count, color in stage_data:
            if count == 0:
                continue
            pct = max((count / max(total_resolved, 1)) * 100, 5)
            segments.append(
                f'<div class="timeline-stage" style="width:{pct:.1f}%;background:{color}" '
                f'title="{name}: {count} findings resolved">'
                f'<span class="timeline-label">{name} ({count})</span>'
                f'</div>'
            )

        total_s = total_ms / 1000

        return (
            f'<div class="section-card">'
            f'<div class="section-header">'
            f'{self._icon("clock", 20, "#38bdf8")}'
            f'<h2>Scan Timeline</h2>'
            f'</div>'
            f'<div class="scan-timeline">{"".join(segments)}</div>'
            f'<div class="timeline-total">Total: {total_s:.1f}s</div>'
            f'</div>'
        )

    def _render_bar_chart(
        self,
        data: dict[str, int],
        colors: dict[str, str] | None,
        total: int,
    ) -> str:
        """Render a horizontal bar chart."""
        if not data or total == 0:
            return '<div style="color:var(--text-muted);font-size:0.85rem">No data available</div>'

        max_val = max(data.values()) if data.values() else 1
        bars = []

        default_colors = [
            "#38bdf8", "#22c55e", "#eab308", "#ef4444",
            "#a78bfa", "#f97316", "#64748b", "#818cf8",
        ]

        for i, (label, count) in enumerate(data.items()):
            if count == 0:
                continue
            pct = (count / max_val * 100) if max_val > 0 else 0
            if colors and label in colors:
                color = colors[label]
            else:
                color = default_colors[i % len(default_colors)]

            short_label = label[:22] + "..." if len(label) > 22 else label
            bars.append(
                f'<div class="bar-row">'
                f'<div class="bar-label" title="{html.escape(label)}">{html.escape(short_label)}</div>'
                f'<div class="bar-container">'
                f'<div class="bar-fill" style="width:{max(pct, 8):.0f}%;background:{color}">{count}</div>'
                f"</div>"
                f'<div class="bar-count">{count}</div>'
                f"</div>"
            )

        return "\n".join(bars)
