"""Generate a mock dashboard with sample data for design iteration.

Usage:
    python scripts/generate_mock_dashboard.py

Opens the dashboard in a browser. Edit html_reporter.py CSS, re-run to see changes.
"""

from src.reporting.html_reporter import HTMLReporter
from src.sast.sarif.schema import (
    Finding, Location, ScanResult, Severity, Verdict,
    StageResolved, Language, UncertaintyScore,
)


def make_finding(id, rule, cwe_id, cwe_name, severity, verdict, file, line, snippet, msg,
                 confidence, fused, stage, cvss=0.0, cvss_sev="", explanation=""):
    return Finding(
        id=id, rule_id=rule, cwe_id=cwe_id, cwe_name=cwe_name,
        severity=severity, verdict=verdict, language=Language.PYTHON,
        location=Location(file_path=file, start_line=line, snippet=snippet),
        sast_confidence=confidence, sast_message=msg,
        uncertainty=UncertaintyScore(
            confidence_uncertainty=1 - confidence,
            complexity_uncertainty=0.3,
            novelty_uncertainty=0.15,
            conflict_uncertainty=0.0,
        ),
        fused_score=fused, stage_resolved=stage,
        cvss_base_score=cvss, cvss_severity=cvss_sev,
        nl_explanation=explanation or "",
    )


findings = [
    make_finding("1", "PY.SQL.INJ", "CWE-89", "SQL Injection",
        Severity.CRITICAL, Verdict.CONFIRMED, "api/users.py", 42,
        'cursor.execute("SELECT * FROM users WHERE id=" + uid)',
        "SQL injection via string concatenation in user lookup",
        0.72, 0.92, StageResolved.LLM, 9.1, "critical",
        "Union-based SQL injection confirmed. User input flows directly into query without parameterization."),
    make_finding("2", "PY.CMD.INJ", "CWE-78", "OS Command Injection",
        Severity.CRITICAL, Verdict.CONFIRMED, "utils/network.py", 15,
        'os.system("ping " + host)',
        "Command injection via os.system with unsanitized input",
        0.90, 0.95, StageResolved.SAST, 9.8, "critical"),
    make_finding("3", "PY.DESER", "CWE-502", "Deserialization of Untrusted Data",
        Severity.CRITICAL, Verdict.CONFIRMED, "api/import.py", 67,
        'data = pickle.loads(request.data)',
        "Unsafe deserialization of user-supplied data via pickle",
        0.88, 0.90, StageResolved.LLM, 9.8, "critical",
        "Pickle deserialization allows arbitrary code execution. No type validation present."),
    make_finding("4", "PY.PATH", "CWE-22", "Path Traversal",
        Severity.HIGH, Verdict.LIKELY, "storage/files.py", 35,
        'filepath = os.path.join(base_dir, user_path)',
        "Path traversal via user-controlled path component",
        0.65, 0.70, StageResolved.SAST, 7.5, "high"),
    make_finding("5", "PY.XSS", "CWE-79", "Cross-site Scripting",
        Severity.HIGH, Verdict.LIKELY, "views/profile.py", 88,
        'return f"<h1>Welcome, {name}</h1>"',
        "Reflected XSS via unsanitized user name in HTML response",
        0.70, 0.68, StageResolved.GRAPH, 6.1, "medium"),
    make_finding("6", "PY.HARDCODED", "CWE-798", "Hardcoded Credentials",
        Severity.HIGH, Verdict.LIKELY, "config/settings.py", 5,
        'DB_PASSWORD = "admin123"',
        "Hardcoded database password in configuration file",
        0.92, 0.75, StageResolved.SAST, 9.8, "critical"),
    make_finding("7", "PY.CRYPTO", "CWE-327", "Broken Cryptographic Algorithm",
        Severity.MEDIUM, Verdict.LIKELY, "auth/hash.py", 22,
        'digest = hashlib.md5(password.encode()).hexdigest()',
        "MD5 used for password hashing — cryptographically broken",
        0.95, 0.72, StageResolved.SAST, 7.5, "high"),
    make_finding("8", "PY.XXE", "CWE-611", "XML External Entity",
        Severity.HIGH, Verdict.LIKELY, "parsers/xml_import.py", 14,
        'tree = etree.parse(uploaded_file)',
        "XML parser allows external entity expansion",
        0.60, 0.65, StageResolved.SAST, 7.5, "high"),
    make_finding("9", "PY.LDAP", "CWE-90", "LDAP Injection",
        Severity.HIGH, Verdict.LIKELY, "auth/ldap.py", 31,
        'conn.search_s(base_dn, ldap.SCOPE_SUBTREE, f"(uid={username})")',
        "LDAP query constructed with unsanitized user input",
        0.55, 0.62, StageResolved.SAST, 9.1, "critical"),
    make_finding("10", "PY.PATH2", "CWE-22", "Path Traversal",
        Severity.HIGH, Verdict.POTENTIAL, "api/download.py", 12,
        'return send_file(os.path.join(root, filename))',
        "Potential path traversal in file download endpoint",
        0.55, 0.42, StageResolved.GRAPH, 5.3, "medium"),
    make_finding("11", "PY.OPEN", "CWE-94", "Code Injection",
        Severity.MEDIUM, Verdict.POTENTIAL, "utils/eval.py", 8,
        'result = eval(user_expression)',
        "Dynamic code evaluation with user-supplied expression",
        0.50, 0.38, StageResolved.SAST, 9.8, "critical"),
    make_finding("12", "PY.LOG", "CWE-209", "Information Exposure",
        Severity.LOW, Verdict.POTENTIAL, "middleware/error.py", 45,
        'logger.error(f"Stack trace: {traceback.format_exc()}")',
        "Stack trace information logged — may expose internals",
        0.40, 0.30, StageResolved.SAST, 5.3, "medium"),
]

result = ScanResult(
    findings=findings,
    scan_target="Vulnerable_Repos/04_docvault",
    languages_detected=[Language.PYTHON],
    total_files_scanned=14,
    total_lines_scanned=2850,
    scan_duration_ms=41200,
    resolved_at_sast=8,
    resolved_at_graph=2,
    resolved_at_llm=2,
    unresolved=0,
)

reporter = HTMLReporter(auto_open=True)
path = reporter.generate(result)
print(f"Mock dashboard: {path}")
print("Edit src/reporting/html_reporter.py CSS, then re-run this script to preview.")
