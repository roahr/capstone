"""
Shared pytest fixtures for the SEC-C test suite.

Provides reusable objects that represent common test data across
all unit and integration tests.
"""

from __future__ import annotations

import json

import pytest

from src.sast.sarif.schema import (
    AttackerVerdict,
    DefenderVerdict,
    Finding,
    GraphValidation,
    Language,
    LLMValidation,
    Location,
    ScanResult,
    Severity,
    StageResolved,
    TaintFlow,
    TaintFlowStep,
    UncertaintyScore,
    Verdict,
)


# ---------------------------------------------------------------------------
# Individual finding fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_finding() -> Finding:
    """A realistic SQL injection Finding with taint flow."""
    return Finding(
        id="abc123deadbeef00",
        rule_id="py/sql-injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity=Severity.CRITICAL,
        verdict=Verdict.UNKNOWN,
        language=Language.PYTHON,
        location=Location(
            file_path="src/app/db.py",
            start_line=42,
            end_line=42,
            start_column=5,
            snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        ),
        taint_flow=TaintFlow(
            steps=[
                TaintFlowStep(
                    location=Location(file_path="src/app/views.py", start_line=10),
                    label="user input from request.args",
                    kind="source",
                ),
                TaintFlowStep(
                    location=Location(file_path="src/app/views.py", start_line=15),
                    label="passed to get_user()",
                    kind="intermediate",
                ),
                TaintFlowStep(
                    location=Location(file_path="src/app/db.py", start_line=42),
                    label="cursor.execute(query)",
                    kind="sink",
                ),
            ]
        ),
        sast_confidence=0.85,
        sast_message="User-controlled value flows into SQL query without parameterization",
        sast_tool="codeql",
        uncertainty=UncertaintyScore(
            confidence_uncertainty=0.15,
            complexity_uncertainty=0.4,
            novelty_uncertainty=0.15,
            conflict_uncertainty=0.0,
        ),
    )


# ---------------------------------------------------------------------------
# Batch of findings with varied severities
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_findings_batch() -> list[Finding]:
    """Five findings with different severities and CWEs."""
    return [
        Finding(
            id="find-001",
            rule_id="py/sql-injection",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            severity=Severity.CRITICAL,
            language=Language.PYTHON,
            location=Location(file_path="app.py", start_line=10),
            sast_confidence=0.9,
            sast_message="SQL injection via f-string",
        ),
        Finding(
            id="find-002",
            rule_id="py/command-injection",
            cwe_id="CWE-78",
            cwe_name="OS Command Injection",
            severity=Severity.HIGH,
            language=Language.PYTHON,
            location=Location(file_path="utils.py", start_line=25),
            sast_confidence=0.75,
            sast_message="Command injection via os.system",
        ),
        Finding(
            id="find-003",
            rule_id="py/xss",
            cwe_id="CWE-79",
            cwe_name="Cross-site Scripting",
            severity=Severity.MEDIUM,
            language=Language.PYTHON,
            location=Location(file_path="templates.py", start_line=50),
            sast_confidence=0.6,
            sast_message="Reflected XSS in template",
        ),
        Finding(
            id="find-004",
            rule_id="py/path-traversal",
            cwe_id="CWE-22",
            cwe_name="Path Traversal",
            severity=Severity.LOW,
            language=Language.PYTHON,
            location=Location(file_path="files.py", start_line=8),
            sast_confidence=0.4,
            sast_message="Possible path traversal",
        ),
        Finding(
            id="find-005",
            rule_id="py/info-leak",
            cwe_id="CWE-200",
            cwe_name="Information Exposure",
            severity=Severity.INFO,
            language=Language.PYTHON,
            location=Location(file_path="errors.py", start_line=15),
            sast_confidence=0.3,
            sast_message="Stack trace exposed in error page",
        ),
    ]


# ---------------------------------------------------------------------------
# SARIF JSON fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_sarif_json() -> str:
    """A valid SARIF 2.1.0 JSON string with two results."""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.18.0",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "shortDescription": {
                                    "text": "SQL Injection"
                                },
                                "fullDescription": {
                                    "text": "User input concatenated into SQL query"
                                },
                                "defaultConfiguration": {"level": "error"},
                                "properties": {
                                    "tags": [
                                        "security",
                                        "external/cwe/cwe-89",
                                    ],
                                    "precision": "high",
                                },
                            },
                            {
                                "id": "py/command-injection",
                                "shortDescription": {
                                    "text": "Command Injection"
                                },
                                "defaultConfiguration": {"level": "warning"},
                                "properties": {
                                    "tags": [
                                        "security",
                                        "external/cwe/cwe-78",
                                    ],
                                    "precision": "medium",
                                },
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "SQL injection via f-string"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.py"},
                                    "region": {
                                        "startLine": 42,
                                        "endLine": 42,
                                        "startColumn": 5,
                                        "snippet": {
                                            "text": 'cursor.execute(f"SELECT ...")'
                                        },
                                    },
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": "src/views.py"
                                                        },
                                                        "region": {
                                                            "startLine": 10
                                                        },
                                                    },
                                                    "message": {
                                                        "text": "user input"
                                                    },
                                                },
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": "src/views.py"
                                                        },
                                                        "region": {
                                                            "startLine": 15
                                                        },
                                                    },
                                                    "message": {
                                                        "text": "passed to db function"
                                                    },
                                                },
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": "src/db.py"
                                                        },
                                                        "region": {
                                                            "startLine": 42
                                                        },
                                                    },
                                                    "message": {
                                                        "text": "SQL sink"
                                                    },
                                                },
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    },
                    {
                        "ruleId": "py/command-injection",
                        "level": "warning",
                        "message": {
                            "text": "Command injection via subprocess"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/utils.py"
                                    },
                                    "region": {
                                        "startLine": 25,
                                        "startColumn": 10,
                                    },
                                }
                            }
                        ],
                        "properties": {
                            "confidence": 0.72,
                        },
                    },
                ],
            }
        ],
    }
    return json.dumps(sarif)


# ---------------------------------------------------------------------------
# ScanResult fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_scan_result(sample_findings_batch: list[Finding]) -> ScanResult:
    """ScanResult populated with cascade statistics."""
    return ScanResult(
        findings=sample_findings_batch,
        scan_target="/tmp/test-project",
        languages_detected=[Language.PYTHON],
        total_files_scanned=20,
        total_lines_scanned=5000,
        scan_duration_ms=1234.5,
        resolved_at_sast=3,
        resolved_at_graph=1,
        resolved_at_llm=1,
        unresolved=0,
    )
