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
        dangerous_functions=["open", "os.path.join", "send_file", "send_from_directory"],
        description="Potential path traversal via user-controlled file path",
    ),
    VulnPattern(
        name="pickle_deserialization",
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        severity=Severity.CRITICAL,
        node_types=["call"],
        dangerous_functions=["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load",
                           "marshal.loads", "shelve.open"],
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
        node_types=["assignment", "expression_statement"],
        dangerous_functions=[],
        description="Hardcoded password or API key detected",
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
        node_types=["call_expression", "assignment_expression"],
        dangerous_functions=["Object.assign", "merge", "extend", "defaults"],
        description="Potential prototype pollution via recursive merge",
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

        for ext in LANGUAGE_EXTENSIONS:
            for file_path in dir_path.rglob(f"*{ext}"):
                # Skip common non-source directories
                parts = file_path.parts
                if any(p in parts for p in ("node_modules", ".git", "__pycache__",
                                            "venv", ".venv", "vendor", "build", "dist")):
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
        for dangerous in pattern.dangerous_functions:
            if func_name == dangerous or func_name.endswith(f".{dangerous}"):
                # After matching dangerous function, check for safe usage
                if self._is_safe_usage(node, pattern, source_lines):
                    return False  # Safe usage detected, don't flag
                return True
            # Also match if the node text contains the dangerous function
            if dangerous in func_name:
                # After matching dangerous function, check for safe usage
                if self._is_safe_usage(node, pattern, source_lines):
                    return False  # Safe usage detected, don't flag
                return True

        return False

    def _extract_function_name(self, node: Any) -> str | None:
        """Extract the function/method name from a call node."""
        try:
            node_text = node.text.decode("utf-8", errors="replace") if node.text else ""

            # For call nodes, the function is typically the first child
            if node.type in ("call", "call_expression", "method_invocation"):
                for child in node.children:
                    if child.type in ("identifier", "attribute", "dotted_name",
                                     "member_expression", "field_identifier",
                                     "scoped_identifier"):
                        return child.text.decode("utf-8", errors="replace") if child.text else None
                    # Handle chained calls like obj.method()
                    if child.type in ("attribute", "member_expression"):
                        return child.text.decode("utf-8", errors="replace") if child.text else None

            # For assignment that might contain innerHTML
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
            return self._is_safe_sql(node, func_name)
        elif pattern.cwe_id == "CWE-78":
            return self._is_safe_command(node, func_name)
        elif pattern.cwe_id == "CWE-95":
            return self._is_safe_eval(node, func_name)
        elif pattern.cwe_id == "CWE-22":
            return self._is_safe_path(node, func_name, source_lines)
        elif pattern.cwe_id == "CWE-502":
            return self._is_safe_deserialization(node, func_name)

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
        Detect safe parameterized SQL queries.

        Safe patterns:
        - cursor.execute("SELECT ... WHERE x = ?", (param,))
        - cursor.execute("SELECT ... WHERE x = %s", [param])
        - cursor.execute("SELECT ... WHERE x = :name", {"name": val})

        The call must have 2+ arguments, and the first argument must be a
        string literal containing a placeholder (?, %s, or :param_name).
        """
        args = self._get_call_arguments(node)
        if len(args) < 2:
            return False

        first_arg = args[0]
        first_text = self._node_text(first_arg)

        # Check if the first argument is a string literal (not an f-string or variable)
        is_string_literal = first_arg.type in ("string", "concatenated_string")
        if not is_string_literal:
            return False

        # Check for parameterized placeholders in the query string
        has_placeholder = (
            "?" in first_text
            or "%s" in first_text
            or "%()" in first_text  # %(name)s style
        )
        # Also detect :param_name style (named parameters)
        if not has_placeholder:
            import re
            has_placeholder = bool(re.search(r":\w+", first_text))

        if not has_placeholder:
            return False

        # Verify the second argument is a tuple, list, or dict (parameters)
        second_arg = args[1]
        if second_arg.type in ("tuple", "list", "dictionary", "set"):
            return True

        # Also accept if second arg is a variable (could be params)
        # but only if the first arg definitely has placeholders
        if second_arg.type in ("identifier",):
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
        safe_indicators = [
            "realpath",
            "os.path.realpath",
            "os.path.abspath",
            "startswith(",
            "Path.resolve",
            ".resolve()",
        ]

        found_count = sum(1 for indicator in safe_indicators if indicator in context)

        # Require at least two indicators (e.g., realpath + startswith)
        # to reduce false negatives
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
        """Detect hardcoded passwords, API keys, and secrets."""
        try:
            node_text = node.text.decode("utf-8", errors="replace").lower() if node.text else ""
        except Exception:
            return False

        secret_keywords = ["password", "passwd", "secret", "api_key", "apikey",
                         "access_token", "auth_token", "private_key"]

        for keyword in secret_keywords:
            if keyword in node_text and "=" in node_text:
                # Check it's an assignment with a string literal value
                if any(q in node_text for q in ['"', "'", '`']):
                    # Exclude common false positives
                    fp_patterns = ["getenv", "environ", "config", "os.", "env.",
                                  "none", "null", "empty", "placeholder", "xxx", "todo"]
                    if not any(fp in node_text for fp in fp_patterns):
                        return True
        return False
