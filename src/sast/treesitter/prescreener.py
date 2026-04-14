"""
Tree-sitter Pre-screener: Fast pattern-based vulnerability pre-screening.

Performs rapid AST-level pattern matching before the heavier CodeQL analysis.
Identifies obvious vulnerability patterns and clearly safe code to optimize
the pipeline — reducing unnecessary CodeQL database creation time.

Supports: Python, JavaScript, Java, C/C++, Go
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter

from src.sast.sarif.schema import Finding, Language, Location, Severity, TaintFlow, TaintFlowStep

logger = logging.getLogger(__name__)

# Language extension mapping
LANGUAGE_EXTENSIONS: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".c": Language.C,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".h": Language.C,
    ".hpp": Language.CPP,
    ".go": Language.GO,
}


@dataclass
class VulnPattern:
    """A vulnerability pattern to match against AST nodes."""
    name: str
    cwe_id: str
    cwe_name: str
    severity: Severity
    node_types: list[str]  # tree-sitter node types to look for
    dangerous_functions: list[str]  # function names considered dangerous
    description: str
    confidence: float = 0.7  # pre-screener confidence is lower than CodeQL


# ──────────────────────────────────────────────────────────────────────────────
# Language-specific vulnerability pattern catalogs
# ──────────────────────────────────────────────────────────────────────────────

PYTHON_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        name="sensitive_log",
        cwe_id="CWE-532",
        cwe_name="Insertion of Sensitive Information into Log File",
        severity=Severity.MEDIUM,
        node_types=["call"],
        dangerous_functions=["print", "logging.info", "logging.debug", "logging.warning",
                           "logging.error", "logger.info", "logger.debug",
                           "logger.warning", "logger.error", "log.info"],
        description="Sensitive data (password, secret, token) written to log/stdout",
    ),
    VulnPattern(
        name="sql_injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity=Severity.CRITICAL,
        node_types=["call", "string", "concatenated_string", "binary_operator"],
        dangerous_functions=["execute", "executemany", "raw", "cursor.execute"],
        description="Potential SQL injection via string concatenation/formatting in query",
    ),
    VulnPattern(
        name="os_command_injection",
        cwe_id="CWE-78",
        cwe_name="OS Command Injection",
        severity=Severity.CRITICAL,
        node_types=["call"],
        dangerous_functions=["os.system", "os.popen", "subprocess.call", "subprocess.run",
                           "subprocess.Popen", "commands.getoutput"],
        description="Potential OS command injection via unsanitized input",
    ),
    VulnPattern(
        name="path_traversal",
        cwe_id="CWE-22",
        cwe_name="Path Traversal",
        severity=Severity.HIGH,
        node_types=["call"],
        # Note: "open" only matches builtin open() — obj.open() excluded by matcher
        dangerous_functions=["open", "os.path.join", "send_file", "send_from_directory"],
        description="Potential path traversal via user-controlled file path",
    ),
    VulnPattern(
        name="pickle_deserialization",
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        severity=Severity.CRITICAL,
        node_types=["call"],
        # shelve.open is fully-qualified to avoid matching file.open()
        dangerous_functions=["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load",
                           "marshal.loads", "shelve.open", "dill.loads", "dill.load"],
        description="Deserialization of untrusted data can lead to RCE",
    ),
    VulnPattern(
        name="xss",
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        severity=Severity.HIGH,
        node_types=["call"],
        dangerous_functions=["render_template_string", "Markup", "mark_safe", "format_html"],
        description="Potential XSS via unescaped user input in HTML output",
    ),
    VulnPattern(
        name="hardcoded_secret",
        cwe_id="CWE-798",
        cwe_name="Hardcoded Credentials",
        severity=Severity.HIGH,
        # Python: assignment (SECRET_KEY = 'x'), expression_statement wraps it
        node_types=["assignment"],
        dangerous_functions=[],
        description="Hardcoded password or API key detected",
    ),
    VulnPattern(
        name="ssrf",
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery",
        severity=Severity.HIGH,
        node_types=["call"],
        dangerous_functions=["requests.get", "requests.post", "requests.put",
                           "requests.delete", "requests.request", "requests.head",
                           "httpx.get", "httpx.post", "urllib.request.urlopen",
                           "urllib.urlopen", "http.client.HTTPConnection",
                           "aiohttp.ClientSession"],
        description="SSRF via user-controlled URL passed to HTTP client",
    ),
    VulnPattern(
        name="open_redirect",
        cwe_id="CWE-601",
        cwe_name="Open Redirect",
        severity=Severity.HIGH,
        node_types=["call"],
        dangerous_functions=["redirect", "flask.redirect", "HttpResponseRedirect"],
        description="Open redirect via unvalidated user-supplied URL",
    ),
    VulnPattern(
        name="weak_crypto",
        cwe_id="CWE-327",
        cwe_name="Use of Weak Cryptographic Algorithm",
        severity=Severity.HIGH,
        node_types=["call"],
        dangerous_functions=["hashlib.md5", "hashlib.sha1", "hashlib.new",
                           "Crypto.Hash.MD5.new", "MD5.new"],
        description="Weak cryptographic algorithm (MD5, SHA1) — use SHA-256 or bcrypt",
    ),
    VulnPattern(
        name="sensitive_log",
        cwe_id="CWE-532",
        cwe_name="Insertion of Sensitive Information into Log File",
        severity=Severity.MEDIUM,
        node_types=["call"],
        dangerous_functions=["print", "logging.info", "logging.debug", "logging.warning",
                           "logging.error", "logger.info", "logger.debug",
                           "logger.warning", "logger.error", "log.info"],
        description="Sensitive data (password, token, secret) written to log/stdout",
    ),
    VulnPattern(
        name="eval_injection",
        cwe_id="CWE-95",
        cwe_name="Eval Injection",
        severity=Severity.CRITICAL,
        node_types=["call"],
        dangerous_functions=["eval", "exec", "compile", "__import__"],
        description="Dynamic code execution with potentially untrusted input",
    ),
]

JAVASCRIPT_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        name="sensitive_log",
        cwe_id="CWE-532",
        cwe_name="Insertion of Sensitive Information into Log File",
        severity=Severity.MEDIUM,
        node_types=["call_expression"],
        dangerous_functions=["console.log", "console.error", "console.warn",
                           "console.info", "console.debug", "logger.info",
                           "logger.error", "logger.warn", "logger.debug", "log.info"],
        description="Sensitive data (password, token, secret) passed to logging function",
    ),
    VulnPattern(
        name="insecure_cookie",
        cwe_id="CWE-614",
        cwe_name="Sensitive Cookie Without Secure Flag",
        severity=Severity.MEDIUM,
        node_types=["call_expression"],
        dangerous_functions=["session", "cookie", "res.cookie", "cookieSession"],
        description="Session/cookie configured without secure or httpOnly flags",
    ),
    VulnPattern(
        name="hardcoded_secret",
        cwe_id="CWE-798",
        cwe_name="Hardcoded Credentials",
        severity=Severity.HIGH,
        # JS: variable_declarator (const secret = 'x') and pair in object literal (secret: 'x')
        node_types=["variable_declarator", "pair"],
        dangerous_functions=[],
        description="Hardcoded password or API key in JS variable or object property",
    ),
    VulnPattern(
        name="xss_innerhtml",
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        severity=Severity.HIGH,
        node_types=["assignment_expression", "call_expression"],
        dangerous_functions=["innerHTML", "outerHTML", "document.write", "document.writeln"],
        description="Potential DOM-based XSS via innerHTML or document.write",
    ),
    VulnPattern(
        name="eval_injection",
        cwe_id="CWE-95",
        cwe_name="Eval Injection",
        severity=Severity.CRITICAL,
        node_types=["call_expression"],
        dangerous_functions=["eval", "Function", "setTimeout", "setInterval"],
        description="Dynamic code execution with eval() or Function()",
    ),
    VulnPattern(
        name="sql_injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity=Severity.CRITICAL,
        node_types=["call_expression", "template_string"],
        dangerous_functions=["query", "execute", "raw"],
        description="Potential SQL injection via template literal or concatenation",
    ),
    VulnPattern(
        name="path_traversal",
        cwe_id="CWE-22",
        cwe_name="Path Traversal",
        severity=Severity.HIGH,
        node_types=["call_expression"],
        dangerous_functions=["readFile", "readFileSync", "createReadStream", "path.join",
                           "path.resolve", "res.sendFile"],
        description="Potential path traversal via user-controlled file path",
    ),
    VulnPattern(
        name="prototype_pollution",
        cwe_id="CWE-1321",
        cwe_name="Prototype Pollution",
        severity=Severity.HIGH,
        node_types=["assignment_expression", "subscript_expression"],
        dangerous_functions=["__proto__", "constructor.prototype"],
        description="Prototype pollution via direct __proto__ or constructor.prototype assignment",
    ),
    VulnPattern(
        name="command_injection",
        cwe_id="CWE-78",
        cwe_name="OS Command Injection",
        severity=Severity.CRITICAL,
        node_types=["call_expression"],
        dangerous_functions=["exec", "execSync", "spawn", "spawnSync", "execFile",
                           "child_process.exec", "shell.exec"],
        description="OS command injection via child_process exec/spawn with user input",
    ),
    VulnPattern(
        name="open_redirect",
        cwe_id="CWE-601",
        cwe_name="Open Redirect",
        severity=Severity.HIGH,
        node_types=["call_expression"],
        dangerous_functions=["res.redirect", "response.redirect", "redirect"],
        description="Open redirect via unvalidated user-supplied URL",
    ),
    VulnPattern(
        name="ssrf",
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery",
        severity=Severity.HIGH,
        node_types=["call_expression"],
        # needle, superagent, node-fetch, got, axios all used as HTTP clients
        dangerous_functions=["fetch", "axios.get", "axios.post", "axios",
                           "request.get", "http.get", "https.get", "got",
                           "needle.get", "needle.post", "needle",
                           "superagent.get", "superagent.post",
                           "nodeFetch", "node-fetch"],
        description="SSRF via user-controlled URL passed to HTTP client",
    ),
    VulnPattern(
        name="nosql_injection",
        cwe_id="CWE-943",
        cwe_name="NoSQL Injection",
        severity=Severity.CRITICAL,
        node_types=["call_expression", "template_string"],
        dangerous_functions=["$where", "find", "findOne", "aggregate"],
        description="NoSQL injection via $where with string interpolation or user-controlled filter",
    ),
    VulnPattern(
        name="weak_crypto",
        cwe_id="CWE-327",
        cwe_name="Use of Weak Cryptographic Algorithm",
        severity=Severity.HIGH,
        node_types=["call_expression"],
        # Covers: crypto.createHash('md5'), require('md5'), md5(), sha1()
        dangerous_functions=["createHash", "createCipher", "createCipheriv",
                           "md5", "sha1", "sha256WithRSAEncryption"],
        description="Weak cryptographic algorithm (MD5, SHA1, DES, RC4) — use bcrypt/argon2 for passwords",
    ),
    VulnPattern(
        name="template_xss",
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting via Template Engine",
        severity=Severity.HIGH,
        # EJS <%- %> unescaped output rendered in templates
        node_types=["call_expression"],
        dangerous_functions=["res.render", "response.render", "render"],
        description="Potential XSS via unescaped template variable (EJS <%->, Pug !{})",
    ),
    VulnPattern(
        name="xxe",
        cwe_id="CWE-611",
        cwe_name="XML External Entity",
        severity=Severity.HIGH,
        node_types=["call_expression"],
        dangerous_functions=["parseXmlString", "parseXml", "parseXmlAsync",
                             "libxmljs.parseXmlString", "DOMParser",
                             "new DOMParser"],
        description="XXE via XML parser with external entities enabled (noent:true)",
    ),
]

JAVA_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        name="sql_injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity=Severity.CRITICAL,
        node_types=["method_invocation"],
        dangerous_functions=["executeQuery", "executeUpdate", "execute", "prepareStatement",
                           "createQuery", "createNativeQuery"],
        description="Potential SQL injection via string concatenation in query",
    ),
    VulnPattern(
        name="deserialization",
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        severity=Severity.CRITICAL,
        node_types=["method_invocation", "object_creation_expression"],
        dangerous_functions=["readObject", "readUnshared", "ObjectInputStream",
                           "XMLDecoder", "fromXML"],
        description="Deserialization of untrusted data can lead to RCE",
    ),
    VulnPattern(
        name="path_traversal",
        cwe_id="CWE-22",
        cwe_name="Path Traversal",
        severity=Severity.HIGH,
        node_types=["method_invocation", "object_creation_expression"],
        dangerous_functions=["File", "Paths.get", "FileInputStream", "FileReader"],
        description="Potential path traversal via user-controlled file path",
    ),
    VulnPattern(
        name="xxe",
        cwe_id="CWE-611",
        cwe_name="XML External Entity",
        severity=Severity.HIGH,
        node_types=["method_invocation", "object_creation_expression"],
        dangerous_functions=["DocumentBuilderFactory", "SAXParserFactory",
                           "XMLInputFactory", "TransformerFactory"],
        description="Potential XXE via XML parser without disabled external entities",
    ),
    VulnPattern(
        name="ldap_injection",
        cwe_id="CWE-90",
        cwe_name="LDAP Injection",
        severity=Severity.HIGH,
        node_types=["method_invocation"],
        dangerous_functions=["search", "DirContext.search"],
        description="Potential LDAP injection via unsanitized search filter",
    ),
]

C_CPP_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        name="buffer_overflow",
        cwe_id="CWE-120",
        cwe_name="Buffer Overflow",
        severity=Severity.CRITICAL,
        node_types=["call_expression"],
        dangerous_functions=["strcpy", "strcat", "sprintf", "gets", "scanf",
                           "vsprintf", "strncpy"],
        description="Potential buffer overflow via unsafe string function",
    ),
    VulnPattern(
        name="format_string",
        cwe_id="CWE-134",
        cwe_name="Format String Vulnerability",
        severity=Severity.HIGH,
        node_types=["call_expression"],
        dangerous_functions=["printf", "fprintf", "sprintf", "snprintf", "syslog"],
        description="Potential format string vulnerability — user input as format string",
    ),
    VulnPattern(
        name="command_injection",
        cwe_id="CWE-78",
        cwe_name="OS Command Injection",
        severity=Severity.CRITICAL,
        node_types=["call_expression"],
        dangerous_functions=["system", "popen", "exec", "execl", "execlp", "execle"],
        description="Potential command injection via system() or exec()",
    ),
    VulnPattern(
        name="use_after_free",
        cwe_id="CWE-416",
        cwe_name="Use After Free",
        severity=Severity.CRITICAL,
        node_types=["call_expression"],
        dangerous_functions=["free", "realloc"],
        description="Potential use-after-free — memory accessed after deallocation",
    ),
]

GO_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        name="sql_injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity=Severity.CRITICAL,
        node_types=["call_expression"],
        dangerous_functions=["Query", "QueryRow", "Exec", "db.Query", "db.Exec"],
        description="Potential SQL injection via string concatenation in query",
    ),
    VulnPattern(
        name="command_injection",
        cwe_id="CWE-78",
        cwe_name="OS Command Injection",
        severity=Severity.CRITICAL,
        node_types=["call_expression"],
        dangerous_functions=["exec.Command", "os.StartProcess"],
        description="Potential command injection via os/exec",
    ),
    VulnPattern(
        name="path_traversal",
        cwe_id="CWE-22",
        cwe_name="Path Traversal",
        severity=Severity.HIGH,
        node_types=["call_expression"],
        dangerous_functions=["os.Open", "os.ReadFile", "filepath.Join", "http.ServeFile"],
        description="Potential path traversal via user-controlled file path",
    ),
]

# Map languages to their pattern catalogs
PATTERN_CATALOG: dict[Language, list[VulnPattern]] = {
    Language.PYTHON: PYTHON_PATTERNS,
    Language.JAVASCRIPT: JAVASCRIPT_PATTERNS,
    Language.TYPESCRIPT: JAVASCRIPT_PATTERNS,  # Reuse JS patterns for TS
    Language.JAVA: JAVA_PATTERNS,
    Language.C: C_CPP_PATTERNS,
    Language.CPP: C_CPP_PATTERNS,
    Language.GO: GO_PATTERNS,
}

# Tree-sitter language modules
TREE_SITTER_LANGUAGES: dict[Language, str] = {
    Language.PYTHON: "tree_sitter_python",
    Language.JAVASCRIPT: "tree_sitter_javascript",
    Language.JAVA: "tree_sitter_java",
    Language.C: "tree_sitter_c",
    Language.CPP: "tree_sitter_c",  # C parser handles basic C++ too
    Language.GO: "tree_sitter_go",
}


@dataclass
class PreScreenResult:
    """Result of pre-screening a single file."""
    file_path: str
    language: Language
    findings: list[Finding] = field(default_factory=list)
    is_clearly_safe: bool = False
    scan_time_ms: float = 0.0


class TreeSitterPreScreener:
    """
    Fast AST-based vulnerability pre-screener using Tree-sitter.

    Performs lightweight pattern matching to:
    1. Flag obvious vulnerabilities with high confidence
    2. Identify clearly safe files to skip CodeQL analysis
    3. Provide initial findings that feed into the uncertainty scorer
    """

    def __init__(self, timeout_ms: int = 100):
        self.timeout_ms = timeout_ms
        self._parsers: dict[Language, tree_sitter.Parser] = {}
        self._initialized_languages: set[Language] = set()

    def _get_parser(self, language: Language) -> tree_sitter.Parser | None:
        """Get or create a Tree-sitter parser for the given language."""
        if language in self._parsers:
            return self._parsers[language]

        module_name = TREE_SITTER_LANGUAGES.get(language)
        if not module_name:
            logger.warning(f"No tree-sitter grammar for {language.value}")
            return None

        try:
            import importlib
            lang_module = importlib.import_module(module_name)
            ts_language = tree_sitter.Language(lang_module.language())
            parser = tree_sitter.Parser(ts_language)
            self._parsers[language] = parser
            self._initialized_languages.add(language)
            return parser
        except (ImportError, Exception) as e:
            logger.warning(f"Failed to initialize tree-sitter for {language.value}: {e}")
            return None

    def detect_language(self, file_path: str) -> Language | None:
        """Detect programming language from file extension."""
        ext = Path(file_path).suffix.lower()
        return LANGUAGE_EXTENSIONS.get(ext)

    def prescreen_file(self, file_path: str) -> PreScreenResult:
        """
        Pre-screen a single file for vulnerability patterns.

        Returns findings with relatively low confidence (0.5-0.7) since
        this is a fast pattern match without data flow analysis.
        """
        import time
        start = time.perf_counter()

        language = self.detect_language(file_path)
        if language is None:
            return PreScreenResult(file_path=file_path, language=Language.PYTHON, is_clearly_safe=True)

        result = PreScreenResult(file_path=file_path, language=language)

        try:
            source_bytes = Path(file_path).read_bytes()
        except (OSError, IOError) as e:
            logger.error(f"Cannot read file {file_path}: {e}")
            result.scan_time_ms = (time.perf_counter() - start) * 1000
            return result

        parser = self._get_parser(language)
        if parser is None:
            result.scan_time_ms = (time.perf_counter() - start) * 1000
            return result

        try:
            tree = parser.parse(source_bytes)
        except Exception as e:
            logger.error(f"Parse error for {file_path}: {e}")
            result.scan_time_ms = (time.perf_counter() - start) * 1000
            return result

        source_text = source_bytes.decode("utf-8", errors="replace")
        source_lines = source_text.split("\n")

        patterns = PATTERN_CATALOG.get(language, [])
        findings = self._match_patterns(tree.root_node, patterns, file_path, language, source_lines)
        result.findings = findings

        # If no patterns matched at all, mark as potentially safe
        if not findings:
            result.is_clearly_safe = True

        result.scan_time_ms = (time.perf_counter() - start) * 1000
        return result

    def prescreen_directory(self, directory: str) -> list[PreScreenResult]:
        """Pre-screen all supported files in a directory."""
        results = []
        dir_path = Path(directory)

        # Directories to never scan — vendored libs, build artifacts, test fixtures
        _SKIP_DIRS_ALL = frozenset({
            "node_modules", ".git", "__pycache__", "venv", ".venv",
            "vendor", "build", "dist", "target", ".mvn",
            # Vendored/bundled web assets
            "static", "plugins", "libs", "bower_components", "assets",
            # Test dirs — full of intentional attack strings and mock data
            "test", "tests", "spec", "specs", "__tests__", "integration",
            "integrationtest", "integration_test",
            # Compiled/generated output
            "generated", "gen", ".gradle", ".idea", "coverage",
        })
        # Extra dirs to skip only for JS/TS — build tooling that doesn't
        # contain real app vulnerabilities (bin/, sandbox/, examples/)
        _SKIP_DIRS_JS_ONLY = frozenset({
            "bin", "sandbox", "examples", "scripts", "tools",
        })
        # File suffixes to always skip
        _SKIP_SUFFIXES = frozenset({".min.js", ".min.css", ".bundle.js", "-bundle.js"})

        # Build-configuration files that are never real app code
        _SKIP_FILENAMES = frozenset({
            "gruntfile.js", "gulpfile.js", "rakefile", "makefile",
            "webpack.config.js", "rollup.config.js", "vite.config.js",
            "jest.config.js", "babel.config.js", ".eslintrc.js",
        })

        for ext in LANGUAGE_EXTENSIONS:
            lang = LANGUAGE_EXTENSIONS[ext]
            is_js = lang in (Language.JAVASCRIPT, Language.TYPESCRIPT)

            for file_path in dir_path.rglob(f"*{ext}"):
                # Skip minified / bundled files by name
                if any(file_path.name.endswith(s) for s in _SKIP_SUFFIXES):
                    continue
                # Skip build-configuration files by filename
                if file_path.name.lower() in _SKIP_FILENAMES:
                    continue
                # Skip universal non-source directories
                parts = set(file_path.parts)
                if parts & _SKIP_DIRS_ALL:
                    continue
                # Skip JS-specific build dirs (bin/, sandbox/, examples/)
                if is_js and parts & _SKIP_DIRS_JS_ONLY:
                    continue
                result = self.prescreen_file(str(file_path))
                results.append(result)

        return results

    def _match_patterns(
        self,
        root_node: Any,
        patterns: list[VulnPattern],
        file_path: str,
        language: Language,
        source_lines: list[str],
    ) -> list[Finding]:
        """Match vulnerability patterns against AST nodes."""
        findings: list[Finding] = []

        # Collect all nodes by type via DFS
        nodes_by_type: dict[str, list[Any]] = {}
        stack = [root_node]
        while stack:
            node = stack.pop()
            node_type = node.type
            nodes_by_type.setdefault(node_type, []).append(node)
            for child in node.children:
                stack.append(child)

        for pattern in patterns:
            for node_type in pattern.node_types:
                for node in nodes_by_type.get(node_type, []):
                    match = self._check_node_against_pattern(node, pattern, source_lines)
                    if match:
                        line = node.start_point[0] + 1  # tree-sitter is 0-indexed
                        end_line = node.end_point[0] + 1
                        col = node.start_point[1] + 1

                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""

                        finding = Finding(
                            id=f"ts-{pattern.cwe_id}-{file_path}-{line}",
                            rule_id=f"ts/{pattern.name}",
                            cwe_id=pattern.cwe_id,
                            cwe_name=pattern.cwe_name,
                            severity=pattern.severity,
                            language=language,
                            location=Location(
                                file_path=file_path,
                                start_line=line,
                                end_line=end_line,
                                start_column=col,
                                snippet=snippet,
                            ),
                            sast_confidence=pattern.confidence,
                            sast_message=pattern.description,
                            sast_tool="tree-sitter",
                        )
                        findings.append(finding)

        # Deduplicate by location
        seen: set[str] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            key = f"{f.cwe_id}:{f.location.file_path}:{f.location.start_line}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _check_node_against_pattern(
        self,
        node: Any,
        pattern: VulnPattern,
        source_lines: list[str],
    ) -> bool:
        """Check if an AST node matches a vulnerability pattern."""
        if not pattern.dangerous_functions:
            # For patterns without specific functions (e.g., hardcoded secrets)
            return self._check_generic_pattern(node, pattern, source_lines)

        # Extract the function name being called
        func_name = self._extract_function_name(node)
        if func_name is None:
            return False

        # Check if the function name matches any dangerous function
        # Use precise matching: exact name OR dotted suffix (obj.exec → exec)
        # NOT substring: "exec" must NOT match "executor" or "regExp.exec"
        func_bare = func_name.rsplit(".", 1)[-1] if "." in func_name else func_name
        func_lower = func_name.lower()

        # Pre-compute whether this is a regex-object method call (for all checks below)
        _REGEX_OBJ_INDICATORS = {"regexp", "regex", "re", "pattern", "match",
                                   "matcher", "tokens", "parser", "tokenre",
                                   "tokensre", "data_url_pattern"}
        _is_regex_method = False
        if "." in func_name:
            _obj_part = func_name.rsplit(".", 1)[0].lower()
            _obj_bare = _obj_part.rsplit(".", 1)[-1].lower()
            _is_regex_method = (
                _obj_bare in _REGEX_OBJ_INDICATORS
                or _obj_bare.endswith("re")
                or _obj_bare.endswith("regexp")
                or _obj_bare.endswith("_pattern")
                or _obj_bare.startswith("/")      # regex literal /abc/.exec()
            )

        for dangerous in pattern.dangerous_functions:
            dangerous_bare = dangerous.rsplit(".", 1)[-1] if "." in dangerous else dangerous
            matched = False

            # Exact full match (e.g., func_name == "exec" or "child_process.exec")
            if func_name == dangerous:
                matched = True
            # Dotted suffix: func_name ends with ".exec" and dangerous is "exec"
            # BUT suppress if the caller object is a regex/parser type
            elif func_name.endswith(f".{dangerous}"):
                if _is_regex_method:
                    matched = False
                else:
                    matched = True
            # Dangerous contains a dot prefix (e.g. "child_process.exec") —
            # check if the dangerous function name appears in full
            elif "." in dangerous and dangerous in func_lower:
                matched = True
            # Bare name exact match (e.g. bare func is "exec" matching dangerous "exec")
            # but NOT when the caller object looks like a regex/string/file method
            elif func_bare == dangerous_bare:
                if "." in func_name:
                    # Use pre-computed regex detection
                    if _is_regex_method:
                        matched = False
                    # Exclude: executor callback pattern
                    elif dangerous_bare == "exec" and "executor" in func_name.lower():
                        matched = False
                    # For dotted dangerous functions (shelve.open, pickle.load),
                    # require the module prefix to match
                    elif "." in dangerous:
                        required_prefix = dangerous.rsplit(".", 1)[0].lower()
                        if required_prefix not in func_name.lower():
                            matched = False
                        else:
                            matched = True
                    # Exclude: file/path object .open() — only builtin open() is dangerous
                    elif dangerous_bare == "open":
                        matched = False  # file.open(), path.open() all safe
                    # Exclude: .load/.loads on non-pickle/yaml/marshal objects
                    elif dangerous_bare in ("load", "loads") and not any(
                        safe_mod in func_name.lower()
                        for safe_mod in ("pickle", "marshal", "yaml", "dill", "shelve")
                    ):
                        matched = False
                    else:
                        matched = True
                else:
                    # func_name has no dot (bare function call like open(), exec())
                    # If the dangerous pattern requires a module prefix, enforce it
                    if "." in dangerous:
                        matched = False  # bare open() should NOT match shelve.open
                    else:
                        matched = True

            if matched:
                if self._is_safe_usage(node, pattern, source_lines):
                    return False
                return True

        return False

    def _extract_function_name(self, node: Any) -> str | None:
        """Extract the function/method name from a call node.

        Returns the dotted call expression, e.g.:
        - connection.executeQuery(q)  → 'connection.executeQuery'
        - exec('cmd')                 → 'exec'
        - obj.method()                → 'obj.method'
        - regExp.exec(str)            → 'regExp.exec'
        """
        try:
            node_text = node.text.decode("utf-8", errors="replace") if node.text else ""

            if node.type == "object_creation_expression":
                # Java: new File(...) → return "File"
                for child in node.children:
                    if child.type in ("type_identifier", "identifier", "scoped_type_identifier"):
                        return child.text.decode("utf-8", errors="replace") if child.text else None
                return None

            if node.type in ("call", "call_expression", "method_invocation"):
                # Collect identifiers before the argument list
                # For Java method_invocation: [identifier, '.', identifier, argument_list]
                # For JS call_expression: [member_expression/identifier, arguments]
                # For Python call: [attribute/identifier, argument_list]
                ident_parts: list[str] = []
                for child in node.children:
                    if child.type == "argument_list" or child.type == "arguments":
                        break
                    if child.type in ("identifier", "field_identifier"):
                        ident_parts.append(child.text.decode("utf-8", errors="replace")
                                           if child.text else "")
                    elif child.type in ("attribute", "member_expression", "dotted_name",
                                        "scoped_identifier", "selector_expression"):
                        # Return the full attribute/member/selector text directly
                        return child.text.decode("utf-8", errors="replace") if child.text else None
                    # Skip punctuation (dots, parens)

                if len(ident_parts) >= 2:
                    # Java: [object, method] → "object.method"
                    return ".".join(p for p in ident_parts if p)
                elif len(ident_parts) == 1:
                    return ident_parts[0]

            # For assignment/expression nodes (innerHTML etc.)
            if node.type in ("assignment_expression", "expression_statement"):
                return node_text

            return node_text if len(node_text) < 200 else None
        except Exception:
            return None

    def _is_safe_usage(
        self,
        node: Any,
        pattern: VulnPattern,
        source_lines: list[str],
    ) -> bool:
        """
        Check if a matched dangerous function call is actually used safely.

        Inspects AST arguments and surrounding context to detect safe usage
        patterns specific to each CWE category. Returns True if the usage
        is safe and the finding should be suppressed.
        """
        func_name = self._extract_function_name(node) or ""

        if pattern.cwe_id == "CWE-89":
            # Quick guard: JSON.parse / JSON.stringify / string-split are never SQL
            func_lower_check = func_name.lower() if func_name else ""
            if any(safe in func_lower_check for safe in
                   ["json.parse", "json.stringify", "rawheaders"]):
                return True
            return self._is_safe_sql(node, func_name)
        elif pattern.cwe_id == "CWE-78":
            return self._is_safe_command(node, func_name)
        elif pattern.cwe_id == "CWE-95":
            return self._is_safe_eval(node, func_name)
        elif pattern.cwe_id == "CWE-22":
            return self._is_safe_path(node, func_name, source_lines)
        elif pattern.cwe_id == "CWE-502":
            return self._is_safe_deserialization(node, func_name)
        elif pattern.cwe_id == "CWE-601":
            return self._is_safe_redirect(node, source_lines)
        elif pattern.cwe_id == "CWE-918":
            return self._is_safe_ssrf(node, source_lines)
        elif pattern.cwe_id == "CWE-943":
            return self._is_safe_nosql(node, func_name)
        elif pattern.cwe_id == "CWE-327":
            return self._is_safe_crypto(node)
        elif pattern.cwe_id == "CWE-1321":
            return self._is_safe_merge(node)
        elif pattern.name == "xss_innerhtml":
            return self._is_safe_innerhtml(node, source_lines)
        elif pattern.name == "template_xss":
            return self._is_safe_template_render(node, source_lines)
        elif pattern.name == "sensitive_log":
            return self._is_safe_log(node)
        elif pattern.name == "insecure_cookie":
            return self._is_safe_cookie(node)
        elif pattern.cwe_id == "CWE-611" and "language" not in str(pattern):
            # JS XXE — only flag when noent:true present (Java XXE handled by existing logic)
            return self._is_safe_js_xxe(node)

        return False

    def _get_argument_list_node(self, node: Any) -> Any | None:
        """Extract the argument_list child node from a call node."""
        for child in node.children:
            if child.type in ("argument_list", "arguments"):
                return child
        return None

    def _get_call_arguments(self, node: Any) -> list[Any]:
        """Extract the actual argument nodes from a call node (skipping parens and commas)."""
        arg_list = self._get_argument_list_node(node)
        if arg_list is None:
            return []
        return [
            child for child in arg_list.children
            if child.type not in ("(", ")", ",", "comment")
        ]

    def _node_text(self, node: Any) -> str:
        """Safely get the text content of a node."""
        try:
            return node.text.decode("utf-8", errors="replace") if node.text else ""
        except Exception:
            return ""

    def _is_safe_sql(self, node: Any, func_name: str) -> bool:
        """
        Detect safe SQL query patterns — suppress from flagging.

        Safe patterns:
        1. Python parameterized: execute("SELECT ... WHERE x = ?", (param,))
        2. Python parameterized: execute("SELECT ... WHERE x = %s", [param])
        3. Java prepareStatement with ? placeholders (no string concatenation in literal)
        4. DDL statements with no user-controlled variables (CREATE TABLE, DROP TABLE)
        5. Java executeQuery()/execute() called with NO argument (PreparedStatement)
        """
        import re as _re
        args = self._get_call_arguments(node)
        node_text = self._node_text(node)

        # Java PreparedStatement pattern: called with no arguments means
        # the statement was already bound via setString/setInt
        # e.g.: preparedStatement.execute() or statement.executeQuery()
        if len(args) == 0:
            # No argument = already parameterized PreparedStatement
            return True

        first_arg = args[0]
        first_text = self._node_text(first_arg)
        first_type = first_arg.type

        # Python/Java: first arg is a string literal
        is_string_literal = first_type in (
            "string", "concatenated_string",  # Python
            "string_literal",                  # Java
        )

        if is_string_literal:
            # DDL statements with no user-variable interpolation are safe to flag
            # but we check: does the literal have concat/format with variables?
            upper = first_text.upper()

            # Pure DDL with no concat → these are schema setup, not injection
            is_pure_ddl = any(kw in upper for kw in
                              ("CREATE TABLE", "DROP TABLE", "CREATE SCHEMA",
                               "CREATE INDEX", "ALTER TABLE", "TRUNCATE TABLE"))
            has_user_concat = (
                "+" in node_text          # Java string concat: "... WHERE id = '" + var + "'"
                or ".format(" in node_text  # Python format
                or "%" in node_text and "(%s)" not in node_text  # Python % formatting with vars
                or "${" in node_text       # template literal
            )
            if is_pure_ddl and not has_user_concat:
                return True  # schema DDL with no user input → suppress

            # Java prepareStatement with ? placeholder inside literal → safe
            has_placeholder = (
                "?" in first_text
                or "%s" in first_text
                or "%()" in first_text
            )
            if not has_placeholder:
                has_placeholder = bool(_re.search(r":\w+", first_text))

            if has_placeholder:
                # Ensure no additional concat outside the placeholder
                if "+" not in node_text and ".format(" not in node_text:
                    return True  # purely parameterized

        # Python: 2+ args with literal first arg containing placeholder
        if len(args) >= 2 and is_string_literal:
            if "?" in first_text or "%s" in first_text:
                second_arg = args[1]
                if second_arg.type in ("tuple", "list", "dictionary", "set", "identifier"):
                    return True

        return False

    def _is_safe_command(self, node: Any, func_name: str) -> bool:
        """
        Detect safe subprocess/command execution patterns.

        Safe patterns:
        - subprocess.run(["cmd", "arg1", "arg2"])  (list args, no shell)
        - subprocess.call(["cmd", "arg1"])  (list args, no shell)

        Unsafe if shell=True is present as a keyword argument.
        """
        args = self._get_call_arguments(node)
        if not args:
            return False

        # os.system is never safe with user input -- no list form exists
        if "os.system" in func_name or "os.popen" in func_name:
            return False

        first_arg = args[0]

        # Check if first argument is a list literal (safe: no shell interpretation)
        is_list_arg = first_arg.type == "list"

        if not is_list_arg:
            return False

        # Check for shell=True keyword argument (which would make it unsafe)
        arg_list = self._get_argument_list_node(node)
        if arg_list is not None:
            for child in arg_list.children:
                if child.type == "keyword_argument":
                    child_text = self._node_text(child)
                    if "shell" in child_text and "True" in child_text:
                        return False  # shell=True makes list args unsafe too

        return True

    def _is_safe_eval(self, node: Any, func_name: str) -> bool:
        """
        Detect safe eval alternatives and false-positive method name matches.

        Safe patterns:
        - ast.literal_eval(expr)  (safe alternative to eval)
        - cursor.execute(...)     (not eval/exec -- it's a method call on an object)
        - obj.compile(...)        (not the builtin compile)
        """
        # If the full function name is ast.literal_eval, it's safe
        if "ast.literal_eval" in func_name or "literal_eval" in func_name:
            return True

        # Filter out method calls that happen to contain "exec"/"eval"/"compile"
        # in their name but are not the dangerous builtins.
        # e.g. cursor.execute, re.compile, query.exec are NOT eval/exec injection.
        dangerous_builtins = {"eval", "exec", "compile", "__import__"}
        # Extract the bare function/method name (last segment after dot)
        bare_name = func_name.rsplit(".", 1)[-1] if "." in func_name else func_name

        if bare_name not in dangerous_builtins:
            # The matched name is a method like "execute" not "exec" -- safe
            return True

        # If it's a dotted call like obj.exec(), it's likely not the builtin
        if "." in func_name and bare_name in ("eval", "exec", "compile"):
            # Builtins are called without a module prefix; dotted calls
            # like re.compile or db.exec are different functions
            return True

        return False

    def _is_safe_path(self, node: Any, func_name: str, source_lines: list[str]) -> bool:
        """
        Detect path traversal mitigation in surrounding context.

        Safe patterns (heuristic -- checks surrounding lines):
        - os.path.realpath used before open()
        - filepath.startswith(base) check present nearby
        """
        line_idx = node.start_point[0]  # 0-indexed line number

        # Look at surrounding lines (up to 5 lines before and after)
        start = max(0, line_idx - 5)
        end = min(len(source_lines), line_idx + 3)
        context = "\n".join(source_lines[start:end])

        # Check for common path traversal mitigations in context
        # Suppress obj.open() — Python file/Path object method, not builtin open()
        if "." in func_name and func_name.rsplit(".", 1)[-1] == "open":
            return True  # csp_file.open(), api_key_file.open(), Path(...).open()

        args = self._get_call_arguments(node)

        # path.join(__dirname, ...) is anchored to a known directory — safe
        node_text_lower = self._node_text(node).lower()
        if ("__dirname" in node_text_lower or "app.root_path" in node_text_lower
                or "base_path" in node_text_lower or "webgoathomedirectory" in node_text_lower):
            # Only safe if no user-controlled variable also appears
            user_indicators = ["req.", "request.", "user_", "username", "filename",
                               "user_input", "query[", "body[", "params["]
            if not any(ind in node_text_lower for ind in user_indicators):
                return True

        # path.concat() on an array variable (not filesystem) — e.g., axios toFormData
        if "concat" in func_name.lower() and "path" in func_name.lower():
            return True  # array.concat(), not fs path concat

        if args:
            first_arg = args[0]
            if first_arg.type in ("string", "string_literal", "interpreted_string_literal"):
                first_text = self._node_text(first_arg)
                # Hardcoded literal path — no user-controlled input
                if "${" not in first_text and "%" not in first_text:
                    # But for os.path.join / path.join: only safe if ALL args are literals
                    if "join" in func_name.lower():
                        all_literal = all(
                            a.type in ("string", "string_literal", "interpreted_string_literal",
                                       "identifier")  # identifiers like __dirname are safe
                            for a in args
                        )
                        if all_literal:
                            return True
                    else:
                        return True  # single-arg hardcoded path like fs.readFile('./pkg.json')

        # Strong single-indicator mitigations — one alone is sufficient
        strong_safe = [
            "path.resolve(",          # JS path.resolve() canonicalizes
            "path.resolve(__dirname", # resolve from known base = safe
            "os.path.realpath(",      # Python canonicalize
            "os.path.abspath(",       # Python absolute path
            "canonicalize(",
            "realpath(",
        ]
        if any(ind in context for ind in strong_safe):
            return True

        # Weaker indicators — require two
        weak_safe = [
            "startswith(",
            "Path.resolve(",
            ".resolve()",
            "normalize(",
            "basename(",
        ]
        found_count = sum(1 for ind in weak_safe if ind in context)
        if found_count >= 2:
            return True

        return False

    def _is_safe_deserialization(self, node: Any, func_name: str) -> bool:
        """
        Detect safe deserialization usage.

        Safe patterns:
        - json.loads() / json.load()  (JSON is safe, not arbitrary code exec)
        - yaml.safe_load()  (safe YAML loading)
        """
        # json.loads / json.load is safe -- not arbitrary code execution
        if func_name.startswith("json.") or func_name.startswith("json "):
            return True

        # yaml.safe_load is the safe alternative
        if "safe_load" in func_name:
            return True

        return False

    def _is_safe_redirect(self, node: Any, source_lines: list[str]) -> bool:
        """Return True (safe) only when redirect target is a static string literal."""
        node_text = self._node_text(node).lower()
        # Directly contains user-controlled source
        user_sources = ["req.query", "req.body", "req.params", "request.args",
                        "request.form", "request.values", "req.headers"]
        if any(src in node_text for src in user_sources):
            return False

        # First argument is an identifier with URL-suggestive name (likely tainted)
        args = self._get_call_arguments(node)
        if args:
            first_arg = args[0]
            first_type = first_arg.type
            first_text = self._node_text(first_arg).lower().strip()
            # String literal = safe
            if first_type in ("string", "string_literal"):
                return True
            # Tainted variable names
            tainted_names = {"next_url", "next", "url", "redirect_url", "target",
                              "return_url", "callback", "goto", "destination", "location"}
            if first_type == "identifier" and first_text in tainted_names:
                return False  # likely tainted
        return True

    def _is_safe_ssrf(self, node: Any, source_lines: list[str]) -> bool:
        """Return True (safe) if the URL is a hardcoded literal or config constant.

        Unsafe when:
        - First argument is req.query.*/req.body.* directly
        - First argument is a variable named url/endpoint/target/href (likely tainted)
        - Template literal with user-source interpolation

        Safe when:
        - First argument is a string literal (hardcoded URL)
        - First argument is a config/env var reference
        """
        node_text = self._node_text(node)
        user_sources = ["req.query", "req.body", "req.params", "request.args",
                        "request.form", "user_input", "user_url", "target_url"]

        # Directly flagged: user source in the call text
        if any(src in node_text for src in user_sources):
            return False

        # Also flag template literals interpolating user vars
        if "${" in node_text and any(src in node_text for src in user_sources):
            return False

        # Suppress: function name is .test() — regex test, not HTTP call
        func_name_text = ""
        for child in node.children:
            if child.type in ("member_expression", "identifier", "attribute"):
                func_name_text = self._node_text(child).lower()
                break
        if func_name_text.endswith(".test") or func_name_text == "test":
            return True  # regex .test(url), not HTTP request

        # Suppress: window.location context = client-side same-origin (not SSRF)
        if "window.location" in node_text or "new url(" in node_text.lower():
            return True

        # Check first argument: if it's a short identifier like `url`, `endpoint`,
        # `target`, `href` — likely tainted by upstream req.query assignment
        args = self._get_call_arguments(node)
        if args:
            first_arg = args[0]
            first_type = first_arg.type
            first_text = self._node_text(first_arg).lower().strip()

            # String literal = safe (hardcoded URL)
            if first_type in ("string", "string_literal"):
                return True

            # Template string: safe only if no user-source interpolation
            if first_type == "template_string":
                if "${" not in first_text:
                    return True

            # Identifier with URL-suggestive name = potentially tainted
            # BUT only flag in server-side context — suppress if in lib/ or examples/
            tainted_var_names = {"url", "endpoint", "target", "href", "uri",
                                  "link", "address", "baseurl", "apiurl",
                                  "requesturl", "targeturl", "remoteurl"}
            if first_type == "identifier" and first_text in tainted_var_names:
                # Check surrounding context for req.query/req.body (real server-side taint)
                line_idx = node.start_point[0]
                start = max(0, line_idx - 10)
                end = min(len(source_lines), line_idx + 2)
                context = "\n".join(source_lines[start:end]).lower()
                server_indicators = ["req.query", "req.body", "req.params",
                                      "request.args", "request.form"]
                if any(ind in context for ind in server_indicators):
                    return False  # Confirmed tainted — flag it
                return True  # No evidence of taint — suppress

        return True  # Default: safe

    def _is_safe_nosql(self, node: Any, func_name: str) -> bool:
        """Flag $where calls; safe if no string interpolation present."""
        node_text = self._node_text(node)
        # Only flag if $where is actually in the node text with interpolation
        if "$where" not in node_text:
            return True  # not a $where query — safe for this rule
        # Unsafe if template literal or string concat is used
        unsafe_indicators = ["${", "+ req", "+ user", "` "]
        return not any(ind in node_text for ind in unsafe_indicators)

    def _is_safe_crypto(self, node: Any) -> bool:
        """Flag weak algorithm names (MD5, SHA1, DES, RC4) in createHash or direct calls.

        Safe when:
        - Algorithm is SHA-256 or stronger (sha256, sha384, sha512, bcrypt, argon2, pbkdf2)
        - It's a direct md5/sha1 call but only on non-sensitive data (no password/token context)
        """
        node_text = self._node_text(node).lower()
        weak_algos = ["md5", "sha1", "sha-1", "des", "rc4", "aes-ecb", "3des"]
        safe_algos = ["sha256", "sha384", "sha512", "sha-256", "sha-384", "sha-512",
                      "bcrypt", "argon2", "pbkdf2", "scrypt"]
        # If using a strong algo, it's safe
        if any(algo in node_text for algo in safe_algos):
            return True
        # Flag if weak algo is present
        return not any(algo in node_text for algo in weak_algos)

    def _is_safe_innerhtml(self, node: Any, source_lines: list[str]) -> bool:
        """Suppress xss_innerhtml when the node is not in a browser/DOM context.

        Safe (suppress):
        - File starts with `module.exports` / `export default` — config module
        - Assignment is to a property that looks like config, not DOM node
        - No DOM document/window context nearby
        """
        node_text = self._node_text(node)
        # If clearly a DOM innerHTML/document.write with user data — flag it
        if any(dangerous in node_text for dangerous in
               ["innerHTML", "outerHTML", "document.write", "document.writeln"]):
            # Check surrounding context for user-data flow
            line_idx = node.start_point[0]
            start = max(0, line_idx - 3)
            end = min(len(source_lines), line_idx + 2)
            ctx = "\n".join(source_lines[start:end]).lower()
            # Suppress if in config/module context (no DOM)
            first_lines = "\n".join(source_lines[:5]).lower()
            if ("module.exports" in first_lines or "export default" in first_lines
                    or "module.exports" in node_text.lower()):
                return True  # config file, not DOM
            return False  # real DOM context
        # Not a DOM sink — check if whole node is just a config object
        if "module.exports" in node_text:
            return True
        return False

    def _is_safe_template_render(self, node: Any, source_lines: list[str]) -> bool:
        """Flag res.render() only when user-controlled data is passed in the template context."""
        node_text = self._node_text(node)
        user_sources = ["req.query", "req.body", "req.params", "request.args",
                        "request.form", "request.values", "request.json"]
        return not any(src in node_text for src in user_sources)

    def _is_safe_log(self, node: Any) -> bool:
        """Flag log/print calls only when a sensitive VARIABLE (not a static string) is logged.

        Safe (don't flag):
        - print("password mismatch")         — literal string mentioning the word
        - console.log('[GITHUB_TOKEN OK]')   — static diagnostic string
        - logger.info("invalid password")    — static error message

        Unsafe (flag):
        - print("cracked! password:", password)  — variable `password` in args
        - console.log(req.body)                  — entire request body logged
        - logging.info('{} {}'.format(u, password)) — password variable in format
        """
        args = self._get_call_arguments(node)
        if not args:
            return True  # no args = safe

        sensitive_var_names = {"password", "passwd", "secret", "token", "api_key",
                                "apikey", "private_key", "auth_token", "access_token",
                                "credential", "credentials"}

        for arg in args:
            arg_type = arg.type
            arg_text = self._node_text(arg).lower()

            # Flag if argument is an identifier with a sensitive name
            if arg_type == "identifier" and arg_text in sensitive_var_names:
                return False

            # Flag if argument is req.body, request.form, etc. (entire user input object)
            if arg_type in ("member_expression", "attribute") and any(
                src in arg_text for src in ["req.body", "req.query", "req.params",
                                             "request.form", "request.data", "request.json"]
            ):
                return False

            # Flag if argument is a format/f-string that interpolates a sensitive variable
            if arg_type in ("call", "call_expression", "formatted_string",
                            "concatenated_string", "template_string", "binary_operator"):
                # Check if the call/format includes a sensitive variable name
                if any(var in arg_text for var in sensitive_var_names):
                    return False

        return True  # no sensitive variable found in args — safe

    def _is_safe_cookie(self, node: Any) -> bool:
        """Flag session/cookie calls only when secure or httpOnly flags are explicitly false."""
        node_text = self._node_text(node).lower()
        unsafe_indicators = ["secure: false", "secure:false",
                             "httponly: false", "httponly:false",
                             "samesite: 'none'", 'samesite: "none"']
        return not any(ind in node_text for ind in unsafe_indicators)

    def _is_safe_js_xxe(self, node: Any) -> bool:
        """JS XXE: only flag libxmljs.parseXmlString when noent:true is passed."""
        node_text = self._node_text(node).lower()
        # Unsafe if noent option is explicitly enabled
        unsafe_opts = ["noent:true", "noent: true", "\"noent\":true", "'noent':true"]
        return not any(opt in node_text for opt in unsafe_opts)

    def _is_safe_merge(self, node: Any) -> bool:
        """Prototype pollution: flag __proto__ access or merge with user-controlled props.

        Safe:
        - Object.assign(constructor.prototype, staticProps) — library inheritance pattern
        - constructor.prototype.method = function() {} — safe method definition

        Dangerous:
        - obj['__proto__'] = userInput
        - Object.assign(target, req.body)   — user-controlled merge target
        - merge(obj, req.query)             — user input merged into object
        """
        node_text = self._node_text(node)
        # __proto__ access is always suspicious
        if "__proto__" in node_text:
            return False  # not safe
        # constructor.prototype with user-controlled data is dangerous
        if "constructor.prototype" in node_text or "constructor[" in node_text:
            user_sources = ["req.body", "req.query", "req.params",
                            "request.json", "request.form", "user_input",
                            "JSON.parse(", "body[", "query["]
            # Only flag if user data flows into it
            if any(src in node_text for src in user_sources):
                return False  # dangerous
            return True  # safe — library inheritance
        return True  # no dangerous pattern

    def _check_generic_pattern(
        self,
        node: Any,
        pattern: VulnPattern,
        source_lines: list[str],
    ) -> bool:
        """Check generic patterns (e.g., hardcoded secrets)."""
        if pattern.name == "hardcoded_secret":
            return self._check_hardcoded_secret(node, source_lines)
        return False

    def _check_hardcoded_secret(self, node: Any, source_lines: list[str]) -> bool:
        """Detect hardcoded passwords, API keys, and secrets using AST structure.

        Strategy:
        - Python `assignment` node: walk children to find LHS identifier and RHS node.
          Only flag when RHS node type is `string` (literal), not `call`, `attribute`, etc.
        - JavaScript `variable_declarator` or `pair` node: same approach.
        - LHS name (or key) must match a secret-like keyword.
        - The literal value must be non-trivial (>=6 chars, not a known placeholder).
        """
        _SECRET_KEYWORDS = {
            "password", "passwd", "secret", "api_key", "apikey",
            "access_token", "auth_token", "private_key", "secret_key",
            "jwt_secret", "signing_key", "encryption_key", "zapApiKey",
            "cookiesecret", "cryptokey", "db_password", "db_pass",
        }
        _PLACEHOLDER_VALUES = {
            "", "none", "null", "undefined", "xxx", "todo", "changeme",
            "placeholder", "your_secret_here", "enter_your_key",
            "insert_key_here", "<secret>", "true", "false", "example",
            "test", "sample", "replace_me", "your_key_here",
        }
        # AST node types that represent string literals across languages
        _STRING_NODE_TYPES = {"string", "string_literal", "interpreted_string_literal",
                               "raw_string_literal", "string_fragment"}

        try:
            node_type = node.type
            lhs_name: str | None = None
            rhs_node: Any | None = None

            if node_type == "assignment":
                # Python: assignment → [lhs, '=', rhs]
                children = [c for c in node.children if c.type not in ("=", "comment")]
                if len(children) >= 2:
                    lhs_node = children[0]
                    rhs_node = children[-1]
                    # LHS may be identifier or attribute (e.g. app.config['SECRET'])
                    lhs_text = self._node_text(lhs_node).lower()
                    lhs_name = lhs_text

            elif node_type == "variable_declarator":
                # JS: variable_declarator → [identifier, '=', value]
                children = [c for c in node.children if c.type not in ("=", "comment")]
                if len(children) >= 2:
                    lhs_node = children[0]
                    rhs_node = children[-1]
                    lhs_name = self._node_text(lhs_node).lower()

            elif node_type == "pair":
                # JS object literal: pair → [property_identifier, ':', value]
                children = [c for c in node.children if c.type not in (":", "comment")]
                if len(children) >= 2:
                    lhs_node = children[0]
                    rhs_node = children[-1]
                    lhs_name = self._node_text(lhs_node).lower()

            if lhs_name is None or rhs_node is None:
                return False

            # LHS must match a secret-like keyword (substring match)
            lhs_lower = lhs_name.lower().replace("-", "_").replace(" ", "_")
            if not any(kw in lhs_lower for kw in _SECRET_KEYWORDS):
                return False

            # RHS must resolve to a string literal.
            # Handle: `os.environ.get(...) or 'fallback'` (boolean_operator / logical_expression)
            # and JS `process.env.X || 'fallback'` (binary_expression)
            effective_rhs = rhs_node
            if rhs_node.type in ("boolean_operator", "binary_expression", "logical_expression"):
                # Walk children; take the last string literal child as the fallback
                for child in reversed(rhs_node.children):
                    if child.type in _STRING_NODE_TYPES:
                        effective_rhs = child
                        break

            rhs_type = effective_rhs.type
            if rhs_type not in _STRING_NODE_TYPES:
                return False  # runtime value (function call, env var, attribute access, etc.)

            # Extract the string content
            rhs_text = self._node_text(effective_rhs)
            # Strip surrounding quotes
            value = rhs_text.strip("'\"` \t")

            # Must be non-trivial length
            if len(value) < 4:
                return False

            # Skip placeholder / dummy values
            if value.lower() in _PLACEHOLDER_VALUES:
                return False

            # Skip values that are all repeated chars or obvious filler
            if len(set(value)) <= 2:
                return False

            return True

        except Exception:
            return False
