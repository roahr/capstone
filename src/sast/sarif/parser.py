"""
SARIF 2.1.0 parser and normalization for the SEC-C framework.

Parses SARIF output from CodeQL and other SAST tools, producing
normalized Finding objects for downstream pipeline stages.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import PurePosixPath
from typing import Any

from .schema import (
    Finding,
    Language,
    Location,
    Severity,
    TaintFlow,
    TaintFlowStep,
)

logger = logging.getLogger(__name__)

# Map file extensions to Language enum values.
_EXTENSION_TO_LANGUAGE: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,
    ".cts": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".cpp": Language.CPP,
    ".cxx": Language.CPP,
    ".cc": Language.CPP,
    ".hpp": Language.CPP,
    ".hxx": Language.CPP,
    ".c": Language.C,
    ".h": Language.C,
    ".go": Language.GO,
}

# Map SARIF level strings to Severity enum values.
_SARIF_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

# SARIF precision values mapped to numeric confidence scores.
_PRECISION_TO_CONFIDENCE: dict[str, float] = {
    "very-high": 0.95,
    "high": 0.85,
    "medium": 0.65,
    "low": 0.40,
}


class SARIFParser:
    """Parse SARIF 2.1.0 files into normalized :class:`Finding` objects.

    Supports CodeQL-flavoured SARIF as well as generic SARIF 2.1.0 output
    from other SAST tools.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, sarif_path: str) -> list[Finding]:
        """Parse a SARIF JSON file at *sarif_path* and return findings.

        Raises
        ------
        FileNotFoundError
            If *sarif_path* does not exist.
        json.JSONDecodeError
            If the file does not contain valid JSON.
        ValueError
            If the parsed JSON is not a dict (invalid SARIF envelope).
        """
        path = PurePosixPath(sarif_path)
        # Read with pathlib for encoding resilience.
        from pathlib import Path

        raw = Path(sarif_path).read_text(encoding="utf-8")
        sarif_data = json.loads(raw)
        if not isinstance(sarif_data, dict):
            raise ValueError(
                f"Expected top-level JSON object in SARIF file, "
                f"got {type(sarif_data).__name__}: {path}"
            )
        return self._extract_findings(sarif_data)

    def parse_string(self, sarif_json: str) -> list[Finding]:
        """Parse a SARIF JSON string and return findings.

        Raises
        ------
        json.JSONDecodeError
            If *sarif_json* is not valid JSON.
        ValueError
            If the parsed JSON is not a dict.
        """
        sarif_data = json.loads(sarif_json)
        if not isinstance(sarif_data, dict):
            raise ValueError(
                f"Expected top-level JSON object, got {type(sarif_data).__name__}"
            )
        return self._extract_findings(sarif_data)

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def _extract_findings(self, sarif_data: dict[str, Any]) -> list[Finding]:
        """Walk all SARIF runs/results and return a flat list of findings."""
        findings: list[Finding] = []
        runs: list[dict[str, Any]] = sarif_data.get("runs", [])

        for run in runs:
            tool_name = self._extract_tool_name(run)
            rules_by_id = self._build_rules_index(run)
            results: list[dict[str, Any]] = run.get("results", [])

            for result in results:
                try:
                    finding = self._result_to_finding(result, rules_by_id, tool_name)
                    findings.append(finding)
                except Exception:
                    # Log and skip malformed individual results so that one
                    # bad entry does not prevent parsing of the entire file.
                    logger.warning(
                        "Skipping unparseable SARIF result: %s",
                        result.get("ruleId", "<unknown>"),
                        exc_info=True,
                    )
        return findings

    # ------------------------------------------------------------------
    # Result -> Finding conversion
    # ------------------------------------------------------------------

    def _result_to_finding(
        self,
        result: dict[str, Any],
        rules_by_id: dict[str, dict[str, Any]],
        tool_name: str,
    ) -> Finding:
        """Convert a single SARIF ``result`` object into a :class:`Finding`."""
        rule_id: str = result.get("ruleId", result.get("rule", {}).get("id", ""))
        rule: dict[str, Any] = rules_by_id.get(rule_id, {})

        # Location -----------------------------------------------------------
        location = self._extract_primary_location(result)

        # Severity / confidence ----------------------------------------------
        sarif_level: str = result.get("level", rule.get("defaultConfiguration", {}).get("level", "warning"))
        severity = self._map_severity(sarif_level)
        confidence = self._extract_confidence(result, rule)

        # CWE ----------------------------------------------------------------
        cwe_id, cwe_name = self._extract_cwe(rule)

        # Taint flow ----------------------------------------------------------
        taint_flow = self._extract_taint_flow(result)

        # Language -------------------------------------------------------------
        language = self._detect_language(location.file_path)

        # Message --------------------------------------------------------------
        message = self._extract_message(result, rule)

        # Deterministic ID ----------------------------------------------------
        finding_id = self._generate_id(rule_id, location.file_path, location.start_line)

        # Tags / properties from SARIF result.properties ----------------------
        sarif_props: dict[str, Any] = result.get("properties", {})
        tags: list[str] = list(sarif_props.get("tags", rule.get("properties", {}).get("tags", [])))

        return Finding(
            id=finding_id,
            rule_id=rule_id,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            severity=severity,
            language=language,
            location=location,
            taint_flow=taint_flow,
            sast_confidence=confidence,
            sast_message=message,
            sast_tool=tool_name,
            tags=tags,
            properties=sarif_props,
        )

    # ------------------------------------------------------------------
    # Location helpers
    # ------------------------------------------------------------------

    def _extract_primary_location(self, result: dict[str, Any]) -> Location:
        """Extract the primary physical location from a SARIF result."""
        locations: list[dict[str, Any]] = result.get("locations", [])
        if not locations:
            return Location(file_path="", start_line=0)

        phys: dict[str, Any] = locations[0].get("physicalLocation", {})
        return self._physical_location_to_model(phys)

    def _physical_location_to_model(self, phys: dict[str, Any]) -> Location:
        """Convert a SARIF ``physicalLocation`` to a :class:`Location`."""
        artifact = phys.get("artifactLocation", {})
        file_path: str = artifact.get("uri", "")

        region: dict[str, Any] = phys.get("region", {})
        start_line: int = region.get("startLine", 0)
        end_line: int | None = region.get("endLine")
        start_col: int | None = region.get("startColumn")
        end_col: int | None = region.get("endColumn")
        snippet_obj: dict[str, Any] = region.get("snippet", {})
        snippet: str | None = snippet_obj.get("text")

        # Fall back to contextRegion snippet when region snippet is absent.
        if snippet is None:
            ctx_region: dict[str, Any] = phys.get("contextRegion", {})
            ctx_snippet: dict[str, Any] = ctx_region.get("snippet", {})
            snippet = ctx_snippet.get("text")

        return Location(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            start_column=start_col,
            end_column=end_col,
            snippet=snippet,
        )

    # ------------------------------------------------------------------
    # Taint / code-flow extraction
    # ------------------------------------------------------------------

    def _extract_taint_flow(self, result: dict[str, Any]) -> TaintFlow | None:
        """Extract a :class:`TaintFlow` from SARIF ``codeFlows``.

        Uses the first threadFlow of the first codeFlow (the canonical
        representation used by CodeQL and most SAST tools).  Returns
        ``None`` if the result contains no code-flow information.
        """
        code_flows: list[dict[str, Any]] = result.get("codeFlows", [])
        if not code_flows:
            return None

        thread_flows: list[dict[str, Any]] = code_flows[0].get("threadFlows", [])
        if not thread_flows:
            return None

        tf_locations: list[dict[str, Any]] = thread_flows[0].get("locations", [])
        if not tf_locations:
            return None

        steps: list[TaintFlowStep] = []
        total = len(tf_locations)
        for idx, tf_loc in enumerate(tf_locations):
            loc_wrapper: dict[str, Any] = tf_loc.get("location", {})
            phys: dict[str, Any] = loc_wrapper.get("physicalLocation", {})
            location = self._physical_location_to_model(phys)

            # Label: prefer message.text, fall back to kinds.
            label = loc_wrapper.get("message", {}).get("text", "")

            # Kind heuristic: first step is source, last is sink, rest are
            # intermediate.
            if idx == 0:
                kind = "source"
            elif idx == total - 1:
                kind = "sink"
            else:
                kind = tf_loc.get("kinds", ["intermediate"])[0] if tf_loc.get("kinds") else "intermediate"

            steps.append(TaintFlowStep(location=location, label=label, kind=kind))

        return TaintFlow(steps=steps) if steps else None

    # ------------------------------------------------------------------
    # Severity / confidence mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _map_severity(sarif_level: str) -> Severity:
        """Map a SARIF ``level`` string to a :class:`Severity`.

        Falls back to ``Severity.MEDIUM`` for unrecognised levels.
        """
        return _SARIF_LEVEL_TO_SEVERITY.get(sarif_level.lower(), Severity.MEDIUM)

    @staticmethod
    def _extract_confidence(
        result: dict[str, Any],
        rule: dict[str, Any],
    ) -> float:
        """Derive a numeric confidence score from SARIF properties.

        Resolution order:
        1. ``result.properties.confidence`` (explicit float 0-1)
        2. ``result.properties.precision`` (CodeQL style string)
        3. ``rule.properties.precision``
        4. ``rule.defaultConfiguration.level`` heuristic
        5. Default 0.5
        """
        result_props: dict[str, Any] = result.get("properties", {})

        # 1. Explicit numeric confidence on the result.
        raw_conf = result_props.get("confidence")
        if raw_conf is not None:
            try:
                return float(raw_conf)
            except (TypeError, ValueError):
                pass

        # 2. Precision on the result.
        precision: str | None = result_props.get("precision")
        if precision and precision.lower() in _PRECISION_TO_CONFIDENCE:
            return _PRECISION_TO_CONFIDENCE[precision.lower()]

        # 3. Precision on the rule.
        rule_props: dict[str, Any] = rule.get("properties", {})
        rule_precision: str | None = rule_props.get("precision")
        if rule_precision and rule_precision.lower() in _PRECISION_TO_CONFIDENCE:
            return _PRECISION_TO_CONFIDENCE[rule_precision.lower()]

        # 4. Level-based heuristic from the rule default configuration.
        level: str = rule.get("defaultConfiguration", {}).get("level", "")
        level_map: dict[str, float] = {
            "error": 0.80,
            "warning": 0.60,
            "note": 0.40,
        }
        if level.lower() in level_map:
            return level_map[level.lower()]

        # 5. Fallback.
        return 0.5

    # ------------------------------------------------------------------
    # CWE extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cwe(rule: dict[str, Any]) -> tuple[str, str]:
        """Extract CWE ID and name from a SARIF rule definition.

        Checks ``rule.properties.tags`` (CodeQL uses ``"external/cwe/cwe-79"``
        style tags) and ``rule.properties.cwe`` for explicit values.

        Returns
        -------
        tuple[str, str]
            ``(cwe_id, cwe_name)`` e.g. ``("CWE-79", "Cross-site Scripting")``.
            Both strings are empty when no CWE is found.
        """
        props: dict[str, Any] = rule.get("properties", {})

        cwe_id: str = ""
        cwe_name: str = ""

        # -- Explicit ``cwe`` property (some tools set this) ----------------
        explicit_cwe = props.get("cwe")
        if isinstance(explicit_cwe, str) and explicit_cwe:
            cwe_id = explicit_cwe if explicit_cwe.upper().startswith("CWE-") else f"CWE-{explicit_cwe}"

        # -- Tags scan (CodeQL style: "external/cwe/cwe-79") ----------------
        if not cwe_id:
            tags: list[str] = props.get("tags", [])
            for tag in tags:
                tag_lower = tag.lower()
                if "cwe" in tag_lower:
                    # Extract numeric CWE id from tag strings like
                    # "external/cwe/cwe-79" or "CWE-89".
                    parts = tag_lower.replace("\\", "/").split("/")
                    for part in reversed(parts):
                        part = part.strip()
                        if part.startswith("cwe-"):
                            # Normalise to uppercase "CWE-<number>"
                            number = part[4:]
                            if number.isdigit():
                                cwe_id = f"CWE-{number}"
                                break
                    if cwe_id:
                        break

        # -- Rule short/full description as CWE name fallback ---------------
        if cwe_id and not cwe_name:
            short_desc: dict[str, Any] = rule.get("shortDescription", {})
            cwe_name = short_desc.get("text", "")
            if not cwe_name:
                full_desc: dict[str, Any] = rule.get("fullDescription", {})
                cwe_name = full_desc.get("text", "")

        # -- Explicit CWE name property -------------------------------------
        explicit_name = props.get("cwe-name", props.get("cweName", ""))
        if isinstance(explicit_name, str) and explicit_name:
            cwe_name = explicit_name

        return cwe_id, cwe_name

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_language(file_path: str) -> Language:
        """Detect the programming language from a file extension.

        Falls back to :attr:`Language.PYTHON` for unknown extensions.
        """
        if not file_path:
            return Language.PYTHON

        # Use PurePosixPath so that both Unix and Windows-style URI paths
        # are handled correctly.
        suffix = PurePosixPath(file_path).suffix.lower()
        return _EXTENSION_TO_LANGUAGE.get(suffix, Language.PYTHON)

    # ------------------------------------------------------------------
    # Message extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_message(result: dict[str, Any], rule: dict[str, Any]) -> str:
        """Extract a human-readable message for the finding.

        Prefers the result-level message; falls back to the rule description.
        """
        msg: str = result.get("message", {}).get("text", "")
        if msg:
            return msg

        # Fall back to rule short/full description.
        short: str = rule.get("shortDescription", {}).get("text", "")
        if short:
            return short
        return rule.get("fullDescription", {}).get("text", "")

    # ------------------------------------------------------------------
    # Tool / rule index helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tool_name(run: dict[str, Any]) -> str:
        """Return the tool driver name from a SARIF run, or ``"unknown"``."""
        return run.get("tool", {}).get("driver", {}).get("name", "unknown")

    @staticmethod
    def _build_rules_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Build a dict mapping ``rule.id`` to its full rule object.

        Searches both ``driver.rules`` and ``extensions[*].rules``.
        """
        index: dict[str, dict[str, Any]] = {}

        driver: dict[str, Any] = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rid: str = rule.get("id", "")
            if rid:
                index[rid] = rule

        # Some SARIF files place rules under tool extensions.
        extensions: list[dict[str, Any]] = run.get("tool", {}).get("extensions", [])
        for ext in extensions:
            for rule in ext.get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    index[rid] = rule

        return index

    # ------------------------------------------------------------------
    # ID generation
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_id(rule_id: str, file_path: str, line: int) -> str:
        """Generate a deterministic finding ID.

        The ID is the first 16 hex characters of the SHA-256 hash of the
        concatenation of *rule_id*, *file_path*, and *line*.  This is
        short enough for display yet collision-resistant for practical
        result sets.
        """
        digest = hashlib.sha256(
            f"{rule_id}:{file_path}:{line}".encode("utf-8"),
        ).hexdigest()
        return digest[:16]
