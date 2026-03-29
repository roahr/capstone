"""
Hybrid FAISS + BM25 RAG Knowledge Base for the SEC-C framework.

Provides contextual vulnerability knowledge to the LLM dual-agent
validation stage by combining dense semantic search (FAISS with
sentence-transformer embeddings) and sparse keyword search (BM25).
Results from both retrieval methods are fused using reciprocal rank
fusion with configurable weighting.

The knowledge base indexes two data sources:

1. **CWE Catalog** -- structured weakness descriptions, detection
   methods, and mitigations from MITRE.
2. **NVD CVE Database** -- real-world vulnerability descriptions,
   CVSS scores, and references from NIST.

Usage::

    kb = KnowledgeBase()
    kb.build_from_data(cwe_dir="data/cwe", nvd_dir="data/nvd")

    result = kb.query(cwe_id="CWE-79", code_snippet="user_input = request.GET['q']")
    print(result["cwe_description"])
    print(result["similar_cves"])
"""

from __future__ import annotations

import json
import logging
import os
import pickle
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# Default storage paths relative to project root.
_DEFAULT_FAISS_PATH = Path("data/rag/faiss_index.bin")
_DEFAULT_BM25_PATH = Path("data/rag/bm25_index.pkl")
_DEFAULT_CWE_DATA_PATH = Path("data/rag/cwe_data.json")
_DEFAULT_CVE_DATA_PATH = Path("data/rag/cve_data.json")
_DEFAULT_METADATA_PATH = Path("data/rag/metadata.json")

# OWASP Top 10 (2021) mapping for CWE to OWASP category guidance.
_CWE_TO_OWASP: dict[str, dict[str, str]] = {
    # A01:2021 - Broken Access Control
    "CWE-22": {"category": "A01:2021 Broken Access Control",
               "guidance": "Validate and sanitize all user-supplied file paths. Use chroot jails or path canonicalization. Deny by default."},
    "CWE-23": {"category": "A01:2021 Broken Access Control",
               "guidance": "Prevent relative path traversal by canonicalizing paths and enforcing a whitelist of allowed directories."},
    "CWE-35": {"category": "A01:2021 Broken Access Control",
               "guidance": "Validate path components to prevent traversal sequences. Use strict allowlists."},
    "CWE-59": {"category": "A01:2021 Broken Access Control",
               "guidance": "Avoid following symbolic links in security-sensitive operations. Use O_NOFOLLOW or equivalent."},
    "CWE-200": {"category": "A01:2021 Broken Access Control",
                "guidance": "Apply principle of least privilege to information exposure. Implement proper authorization checks."},
    "CWE-284": {"category": "A01:2021 Broken Access Control",
                "guidance": "Implement role-based access control. Deny by default. Log access control failures."},
    "CWE-285": {"category": "A01:2021 Broken Access Control",
                "guidance": "Implement proper authorization. Use a centralized authorization mechanism."},
    "CWE-352": {"category": "A01:2021 Broken Access Control",
                "guidance": "Use anti-CSRF tokens. Validate the Origin/Referer header. Use SameSite cookie attribute."},
    "CWE-639": {"category": "A01:2021 Broken Access Control",
                "guidance": "Use indirect references. Validate authorization for every object access."},
    "CWE-862": {"category": "A01:2021 Broken Access Control",
                "guidance": "Enforce authorization checks on every request. Use middleware or decorators for consistent enforcement."},
    "CWE-863": {"category": "A01:2021 Broken Access Control",
                "guidance": "Verify that the user has the correct privileges for the requested action."},

    # A02:2021 - Cryptographic Failures
    "CWE-259": {"category": "A02:2021 Cryptographic Failures",
                "guidance": "Never hard-code credentials. Use environment variables or secure vaults."},
    "CWE-261": {"category": "A02:2021 Cryptographic Failures",
                "guidance": "Use strong, well-tested cryptographic algorithms. Avoid custom crypto."},
    "CWE-327": {"category": "A02:2021 Cryptographic Failures",
                "guidance": "Use standard, vetted cryptographic algorithms (AES-256-GCM, SHA-256+). Avoid MD5, SHA-1, DES."},
    "CWE-328": {"category": "A02:2021 Cryptographic Failures",
                "guidance": "Use cryptographic hash functions with sufficient output length. Prefer SHA-256 or better."},
    "CWE-330": {"category": "A02:2021 Cryptographic Failures",
                "guidance": "Use cryptographically secure random number generators (secrets module, /dev/urandom)."},
    "CWE-331": {"category": "A02:2021 Cryptographic Failures",
                "guidance": "Ensure sufficient entropy in random value generation for security-sensitive operations."},
    "CWE-798": {"category": "A02:2021 Cryptographic Failures",
                "guidance": "Never embed credentials in source code. Use secrets management (HashiCorp Vault, AWS Secrets Manager)."},

    # A03:2021 - Injection
    "CWE-20": {"category": "A03:2021 Injection",
               "guidance": "Validate all input against expected formats. Use allowlists over denylists."},
    "CWE-74": {"category": "A03:2021 Injection",
               "guidance": "Use parameterized queries or prepared statements. Never concatenate user input into commands."},
    "CWE-75": {"category": "A03:2021 Injection",
               "guidance": "Sanitize special elements before passing data to interpreters or downstream components."},
    "CWE-77": {"category": "A03:2021 Injection",
               "guidance": "Avoid passing user input to OS commands. Use APIs instead of shell commands."},
    "CWE-78": {"category": "A03:2021 Injection",
               "guidance": "Never construct OS commands from user input. Use subprocess with argument lists, not shell=True."},
    "CWE-79": {"category": "A03:2021 Injection",
               "guidance": "Apply context-aware output encoding. Use Content Security Policy. Sanitize HTML with proven libraries."},
    "CWE-89": {"category": "A03:2021 Injection",
               "guidance": "Use parameterized queries or ORMs exclusively. Never concatenate user input into SQL."},
    "CWE-90": {"category": "A03:2021 Injection",
               "guidance": "Sanitize inputs used in LDAP queries. Use parameterized LDAP search filters."},
    "CWE-94": {"category": "A03:2021 Injection",
               "guidance": "Avoid eval/exec on user input. Use sandboxed environments if code execution is necessary."},
    "CWE-917": {"category": "A03:2021 Injection",
                "guidance": "Avoid evaluating user-controlled expressions. Use safe expression parsers."},

    # A04:2021 - Insecure Design
    "CWE-209": {"category": "A04:2021 Insecure Design",
                "guidance": "Use generic error messages for users. Log detailed errors server-side only."},
    "CWE-256": {"category": "A04:2021 Insecure Design",
                "guidance": "Store credentials using strong one-way hashing (bcrypt, scrypt, Argon2)."},
    "CWE-501": {"category": "A04:2021 Insecure Design",
                "guidance": "Never trust client-side trust boundaries. Validate all inputs server-side."},
    "CWE-522": {"category": "A04:2021 Insecure Design",
                "guidance": "Enforce strong password policies. Use multi-factor authentication."},

    # A05:2021 - Security Misconfiguration
    "CWE-2": {"category": "A05:2021 Security Misconfiguration",
              "guidance": "Review default configurations. Disable unnecessary features and services."},
    "CWE-11": {"category": "A05:2021 Security Misconfiguration",
               "guidance": "Remove ASP.NET debugging configuration in production."},
    "CWE-13": {"category": "A05:2021 Security Misconfiguration",
               "guidance": "Protect configuration files from unauthorized access."},
    "CWE-15": {"category": "A05:2021 Security Misconfiguration",
               "guidance": "Validate system settings controlled by external input."},
    "CWE-16": {"category": "A05:2021 Security Misconfiguration",
               "guidance": "Establish secure configuration baselines. Automate configuration management."},
    "CWE-611": {"category": "A05:2021 Security Misconfiguration",
                "guidance": "Disable XML external entity processing. Use JSON instead of XML where possible."},

    # A06:2021 - Vulnerable and Outdated Components
    "CWE-1104": {"category": "A06:2021 Vulnerable and Outdated Components",
                 "guidance": "Maintain an inventory of dependencies. Use automated dependency scanning (Dependabot, Snyk)."},

    # A07:2021 - Identification and Authentication Failures
    "CWE-287": {"category": "A07:2021 Identification and Authentication Failures",
                "guidance": "Use proven authentication mechanisms. Implement MFA. Limit login attempts."},
    "CWE-384": {"category": "A07:2021 Identification and Authentication Failures",
                "guidance": "Regenerate session IDs after authentication. Invalidate sessions on logout."},
    "CWE-613": {"category": "A07:2021 Identification and Authentication Failures",
                "guidance": "Set appropriate session timeouts. Implement idle and absolute session expiry."},

    # A08:2021 - Software and Data Integrity Failures
    "CWE-345": {"category": "A08:2021 Software and Data Integrity Failures",
                "guidance": "Verify data integrity with digital signatures or HMACs."},
    "CWE-502": {"category": "A08:2021 Software and Data Integrity Failures",
                "guidance": "Never deserialize untrusted data. Use safe serialization formats (JSON)."},
    "CWE-565": {"category": "A08:2021 Software and Data Integrity Failures",
                "guidance": "Do not rely on cookies for security decisions without server-side validation."},

    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-117": {"category": "A09:2021 Security Logging and Monitoring Failures",
                "guidance": "Sanitize log outputs. Use structured logging to prevent log injection."},
    "CWE-223": {"category": "A09:2021 Security Logging and Monitoring Failures",
                "guidance": "Log all security-relevant events with sufficient detail for forensic analysis."},
    "CWE-532": {"category": "A09:2021 Security Logging and Monitoring Failures",
                "guidance": "Never log sensitive data (passwords, tokens, PII). Use log scrubbing."},
    "CWE-778": {"category": "A09:2021 Security Logging and Monitoring Failures",
                "guidance": "Implement comprehensive security logging. Set up alerts for anomalous patterns."},

    # A10:2021 - Server-Side Request Forgery (SSRF)
    "CWE-918": {"category": "A10:2021 Server-Side Request Forgery",
                "guidance": "Validate and sanitize all URLs. Use allowlists for outbound requests. Block internal network ranges."},
}


class KnowledgeBase:
    """Hybrid FAISS + BM25 knowledge base for vulnerability context retrieval.

    Combines dense semantic search (FAISS with all-MiniLM-L6-v2 embeddings)
    and sparse keyword search (Okapi BM25) to retrieve relevant CWE
    descriptions, CVE records, code examples, and OWASP guidance for a
    given vulnerability finding.

    Args:
        faiss_index_path: Path to the serialised FAISS index file.
        bm25_index_path: Path to the pickled BM25 index file.
        cwe_data_path: Path to the JSON file containing parsed CWE entries.
    """

    def __init__(
        self,
        faiss_index_path: str | Path = _DEFAULT_FAISS_PATH,
        bm25_index_path: str | Path = _DEFAULT_BM25_PATH,
        cwe_data_path: str | Path = _DEFAULT_CWE_DATA_PATH,
    ) -> None:
        self._faiss_index_path = Path(faiss_index_path)
        self._bm25_index_path = Path(bm25_index_path)
        self._cwe_data_path = Path(cwe_data_path)
        self._cve_data_path = Path(str(cwe_data_path).replace("cwe_data", "cve_data"))
        self._metadata_path = Path(str(cwe_data_path).replace("cwe_data", "metadata"))

        # Loaded state
        self._faiss_index: Any = None
        self._bm25_index: Any = None
        self._documents: list[dict[str, Any]] = []
        self._cwe_map: dict[str, dict[str, Any]] = {}
        self._cve_entries: list[dict[str, Any]] = []
        self._embedder: Any = None

        # Attempt to load existing indexes
        self._try_load()

    # ------------------------------------------------------------------
    # Building
    # ------------------------------------------------------------------

    def build_from_data(
        self, cwe_dir: str | Path, nvd_dir: str | Path
    ) -> None:
        """Build both FAISS and BM25 indexes from raw data directories.

        This is the main entry point for constructing the knowledge base
        from scratch.  It:

        1. Parses CWE XML and NVD JSON files.
        2. Merges all documents into a unified corpus.
        3. Builds a FAISS inner-product index from sentence-transformer
           embeddings.
        4. Builds a BM25 keyword index from tokenised document texts.
        5. Persists all indexes and metadata to disk.

        Args:
            cwe_dir: Directory containing the CWE XML catalog.
            nvd_dir: Directory containing NVD JSON files.
        """
        from src.llm.rag.cwe_indexer import CWEIndexer
        from src.llm.rag.nvd_indexer import NVDIndexer

        cwe_dir = Path(cwe_dir)
        nvd_dir = Path(nvd_dir)

        # --- Parse CWE data ---
        cwe_indexer = CWEIndexer()
        xml_files = list(cwe_dir.glob("*.xml"))
        cwe_entries: list[dict[str, Any]] = []
        if xml_files:
            cwe_entries = cwe_indexer.parse_cwe_xml(xml_files[0])
            logger.info("Parsed %d CWE entries", len(cwe_entries))
        else:
            logger.warning("No CWE XML files found in %s", cwe_dir)

        self._cwe_map = {e["id"]: e for e in cwe_entries}

        # --- Parse NVD data ---
        nvd_indexer = NVDIndexer()
        json_files = sorted(nvd_dir.glob("*.json"))
        cve_entries: list[dict[str, Any]] = []
        for jf in json_files:
            with open(jf, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for vuln in data.get("vulnerabilities", []):
                entry = nvd_indexer.parse_cve_entry(vuln)
                if entry["description"]:
                    cve_entries.append(entry)

        self._cve_entries = cve_entries
        logger.info("Parsed %d CVE entries", len(cve_entries))

        # --- Build unified document corpus ---
        documents: list[dict[str, Any]] = []

        # Add CWE documents
        for entry in cwe_entries:
            doc = {
                "type": "cwe",
                "id": entry["id"],
                "text": f"{entry['id']} {entry['name']}: {entry['description']}",
                "metadata": entry,
            }
            documents.append(doc)

        # Add CVE documents
        for entry in cve_entries:
            cwes = ", ".join(entry["cwe_ids"]) if entry["cwe_ids"] else ""
            score = entry["cvss_v31_score"] if entry["cvss_v31_score"] else ""
            doc = {
                "type": "cve",
                "id": entry["id"],
                "text": (
                    f"{entry['id']} ({cwes}, CVSS: {score}): "
                    f"{entry['description']}"
                ),
                "metadata": entry,
            }
            documents.append(doc)

        self._documents = documents
        logger.info("Total documents in corpus: %d", len(documents))

        # --- Build FAISS index ---
        texts = [d["text"] for d in documents]
        embeddings = self._get_embeddings(texts)

        try:
            import faiss  # type: ignore[import-untyped]

            dim = embeddings.shape[1]
            self._faiss_index = faiss.IndexFlatIP(dim)
            faiss.normalize_L2(embeddings)
            self._faiss_index.add(embeddings)
            logger.info(
                "Built FAISS index: %d vectors, dim=%d",
                self._faiss_index.ntotal, dim,
            )
        except ImportError:
            logger.warning("FAISS not available; semantic search will be disabled")
            self._faiss_index = None

        # --- Build BM25 index ---
        tokenised_corpus = [self._tokenise(text) for text in texts]
        try:
            from rank_bm25 import BM25Okapi  # type: ignore[import-untyped]
            self._bm25_index = BM25Okapi(tokenised_corpus)
            logger.info("Built BM25 index over %d documents", len(tokenised_corpus))
        except ImportError:
            logger.warning("rank-bm25 not available; keyword search will be disabled")
            self._bm25_index = None

        # --- Persist to disk ---
        self._save()

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def query(
        self,
        cwe_id: str,
        code_snippet: str = "",
        top_k: int = 5,
    ) -> dict[str, Any]:
        """Retrieve contextual vulnerability knowledge.

        Performs a hybrid search combining semantic similarity (FAISS) and
        keyword matching (BM25) to find the most relevant CWE descriptions,
        CVE records, code examples, and OWASP guidance.

        Args:
            cwe_id: CWE identifier (e.g. ``"CWE-79"``).
            code_snippet: Optional code snippet for context-aware retrieval.
            top_k: Number of results to retrieve from each search method
                before fusion.

        Returns:
            A dict with keys:

            - ``cwe_description``: Full CWE text (direct lookup + search).
            - ``similar_cves``: List of relevant CVE entries.
            - ``code_examples``: Vulnerable + patched code pairs.
            - ``owasp_guidance``: Relevant OWASP Top 10 guidance.
        """
        # Normalise CWE ID
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        cwe_id = cwe_id.upper()

        result: dict[str, Any] = {
            "cwe_description": "",
            "similar_cves": [],
            "code_examples": [],
            "owasp_guidance": "",
        }

        # --- Direct CWE lookup ---
        cwe_info = self._cwe_map.get(cwe_id)
        if cwe_info:
            result["cwe_description"] = (
                f"{cwe_info['id']} - {cwe_info['name']}\n\n"
                f"{cwe_info['description']}\n\n"
                f"Detection Methods:\n"
                + "\n".join(f"  - {m}" for m in cwe_info.get("detection_methods", []))
                + "\n\nMitigations:\n"
                + "\n".join(f"  - {m}" for m in cwe_info.get("mitigations", []))
            )

        # --- OWASP guidance ---
        owasp = _CWE_TO_OWASP.get(cwe_id)
        if owasp:
            result["owasp_guidance"] = (
                f"OWASP Category: {owasp['category']}\n"
                f"Guidance: {owasp['guidance']}"
            )

        # --- Hybrid search for similar CVEs ---
        query_text = f"{cwe_id}"
        if code_snippet:
            query_text += f" {code_snippet}"
        if cwe_info:
            query_text += f" {cwe_info['name']} {cwe_info['description'][:200]}"

        if self._documents:
            semantic_results = self._semantic_search(query_text, top_k)
            keyword_results = self._keyword_search(query_text, top_k)
            merged = self._hybrid_merge(semantic_results, keyword_results)

            # Separate CVE and CWE results
            for item in merged[:top_k]:
                doc = item["document"]
                if doc["type"] == "cve":
                    result["similar_cves"].append(doc["metadata"])
                elif doc["type"] == "cwe" and not result["cwe_description"]:
                    # Use searched CWE if direct lookup missed
                    meta = doc["metadata"]
                    result["cwe_description"] = (
                        f"{meta['id']} - {meta['name']}\n\n{meta['description']}"
                    )

        # --- Code examples (from CWE mitigations/consequences context) ---
        result["code_examples"] = self._get_code_examples(cwe_id)

        return result

    # ------------------------------------------------------------------
    # Search methods
    # ------------------------------------------------------------------

    def _semantic_search(
        self, query_text: str, top_k: int
    ) -> list[dict[str, Any]]:
        """FAISS cosine-similarity search over document embeddings.

        Args:
            query_text: Natural-language query string.
            top_k: Number of results to return.

        Returns:
            List of ``{"document": ..., "score": ...}`` dicts, sorted by
            descending similarity.
        """
        if self._faiss_index is None or not self._documents:
            return []

        try:
            import faiss  # type: ignore[import-untyped]

            query_vec = self._get_embeddings([query_text])
            faiss.normalize_L2(query_vec)

            scores, indices = self._faiss_index.search(query_vec, min(top_k, len(self._documents)))

            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < 0 or idx >= len(self._documents):
                    continue
                results.append({
                    "document": self._documents[idx],
                    "score": float(score),
                    "method": "semantic",
                })
            return results

        except Exception as e:
            logger.warning("Semantic search failed: %s", e)
            return []

    def _keyword_search(
        self, query_text: str, top_k: int
    ) -> list[dict[str, Any]]:
        """BM25 keyword ranking over the document corpus.

        Args:
            query_text: Query string (will be tokenised).
            top_k: Number of results to return.

        Returns:
            List of ``{"document": ..., "score": ...}`` dicts, sorted by
            descending BM25 score.
        """
        if self._bm25_index is None or not self._documents:
            return []

        try:
            tokens = self._tokenise(query_text)
            scores = self._bm25_index.get_scores(tokens)

            top_indices = np.argsort(scores)[::-1][:top_k]

            results = []
            for idx in top_indices:
                if scores[idx] <= 0:
                    continue
                results.append({
                    "document": self._documents[idx],
                    "score": float(scores[idx]),
                    "method": "keyword",
                })
            return results

        except Exception as e:
            logger.warning("Keyword search failed: %s", e)
            return []

    def _hybrid_merge(
        self,
        semantic: list[dict[str, Any]],
        keyword: list[dict[str, Any]],
        weight_semantic: float = 0.6,
    ) -> list[dict[str, Any]]:
        """Merge semantic and keyword search results via reciprocal rank fusion.

        Each document receives a fused score computed as::

            score = w_semantic * (1 / (k + rank_semantic))
                  + w_keyword  * (1 / (k + rank_keyword))

        where ``k = 60`` is a smoothing constant (standard RRF practice).

        Args:
            semantic: Results from :meth:`_semantic_search`.
            keyword: Results from :meth:`_keyword_search`.
            weight_semantic: Weight for the semantic component.  The keyword
                weight is ``1 - weight_semantic``.

        Returns:
            Merged and re-ranked list of result dicts.
        """
        k = 60  # RRF smoothing constant
        weight_keyword = 1.0 - weight_semantic

        # Build RRF scores keyed by document ID
        rrf_scores: dict[str, float] = {}
        doc_map: dict[str, dict[str, Any]] = {}

        for rank, item in enumerate(semantic):
            doc_id = item["document"]["id"]
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + (
                weight_semantic / (k + rank + 1)
            )
            doc_map[doc_id] = item["document"]

        for rank, item in enumerate(keyword):
            doc_id = item["document"]["id"]
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + (
                weight_keyword / (k + rank + 1)
            )
            doc_map[doc_id] = item["document"]

        # Sort by fused score
        sorted_ids = sorted(rrf_scores, key=lambda d: rrf_scores[d], reverse=True)

        return [
            {"document": doc_map[doc_id], "score": rrf_scores[doc_id]}
            for doc_id in sorted_ids
        ]

    # ------------------------------------------------------------------
    # Code examples
    # ------------------------------------------------------------------

    @staticmethod
    def _get_code_examples(cwe_id: str) -> list[dict[str, str]]:
        """Return canonical vulnerable / patched code pairs for common CWEs.

        These are curated examples that the LLM agents use as reference
        when evaluating real-world code.

        Args:
            cwe_id: Normalised CWE identifier.

        Returns:
            List of dicts, each with ``vulnerable`` and ``patched`` keys.
        """
        examples: dict[str, list[dict[str, str]]] = {
            "CWE-89": [
                {
                    "vulnerable": (
                        "# SQL Injection - string concatenation\n"
                        "query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n"
                        "cursor.execute(query)"
                    ),
                    "patched": (
                        "# Parameterized query\n"
                        "query = \"SELECT * FROM users WHERE name = %s\"\n"
                        "cursor.execute(query, (user_input,))"
                    ),
                }
            ],
            "CWE-79": [
                {
                    "vulnerable": (
                        "# XSS - unescaped user input in HTML\n"
                        "return f\"<h1>Hello {user_input}</h1>\""
                    ),
                    "patched": (
                        "# Escaped output\n"
                        "from markupsafe import escape\n"
                        "return f\"<h1>Hello {escape(user_input)}</h1>\""
                    ),
                }
            ],
            "CWE-78": [
                {
                    "vulnerable": (
                        "# OS Command Injection\n"
                        "import os\n"
                        "os.system(f\"ping {user_input}\")"
                    ),
                    "patched": (
                        "# Safe subprocess usage\n"
                        "import subprocess\n"
                        "subprocess.run([\"ping\", user_input], check=True)"
                    ),
                }
            ],
            "CWE-22": [
                {
                    "vulnerable": (
                        "# Path Traversal\n"
                        "filepath = os.path.join(base_dir, user_filename)\n"
                        "with open(filepath) as f:\n"
                        "    return f.read()"
                    ),
                    "patched": (
                        "# Safe path handling\n"
                        "filepath = os.path.realpath(os.path.join(base_dir, user_filename))\n"
                        "if not filepath.startswith(os.path.realpath(base_dir)):\n"
                        "    raise ValueError(\"Path traversal detected\")\n"
                        "with open(filepath) as f:\n"
                        "    return f.read()"
                    ),
                }
            ],
            "CWE-502": [
                {
                    "vulnerable": (
                        "# Insecure Deserialization\n"
                        "import pickle\n"
                        "data = pickle.loads(user_bytes)"
                    ),
                    "patched": (
                        "# Safe deserialization\n"
                        "import json\n"
                        "data = json.loads(user_string)"
                    ),
                }
            ],
            "CWE-798": [
                {
                    "vulnerable": (
                        "# Hard-coded credentials\n"
                        "API_KEY = \"sk-abc123secret\"\n"
                        "db_password = \"admin123\""
                    ),
                    "patched": (
                        "# Environment variable credentials\n"
                        "import os\n"
                        "API_KEY = os.environ[\"API_KEY\"]\n"
                        "db_password = os.environ[\"DB_PASSWORD\"]"
                    ),
                }
            ],
            "CWE-327": [
                {
                    "vulnerable": (
                        "# Weak cryptographic algorithm\n"
                        "import hashlib\n"
                        "password_hash = hashlib.md5(password.encode()).hexdigest()"
                    ),
                    "patched": (
                        "# Strong hashing with salt\n"
                        "import bcrypt\n"
                        "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
                    ),
                }
            ],
            "CWE-611": [
                {
                    "vulnerable": (
                        "# XXE vulnerable XML parsing\n"
                        "from xml.etree.ElementTree import parse\n"
                        "tree = parse(user_xml_file)"
                    ),
                    "patched": (
                        "# XXE-safe XML parsing\n"
                        "from defusedxml.ElementTree import parse\n"
                        "tree = parse(user_xml_file)"
                    ),
                }
            ],
            "CWE-918": [
                {
                    "vulnerable": (
                        "# SSRF - unvalidated URL\n"
                        "import requests\n"
                        "resp = requests.get(user_url)"
                    ),
                    "patched": (
                        "# SSRF protection with URL validation\n"
                        "import ipaddress\n"
                        "from urllib.parse import urlparse\n"
                        "parsed = urlparse(user_url)\n"
                        "ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n"
                        "if ip.is_private or ip.is_loopback:\n"
                        "    raise ValueError(\"Internal addresses blocked\")\n"
                        "resp = requests.get(user_url)"
                    ),
                }
            ],
            "CWE-94": [
                {
                    "vulnerable": (
                        "# Code injection via eval\n"
                        "result = eval(user_expression)"
                    ),
                    "patched": (
                        "# Safe expression evaluation\n"
                        "import ast\n"
                        "result = ast.literal_eval(user_expression)"
                    ),
                }
            ],
        }

        return examples.get(cwe_id, [])

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        """Persist all indexes and metadata to disk."""
        for p in [
            self._faiss_index_path,
            self._bm25_index_path,
            self._cwe_data_path,
        ]:
            p.parent.mkdir(parents=True, exist_ok=True)

        # Save FAISS index
        if self._faiss_index is not None:
            try:
                import faiss  # type: ignore[import-untyped]
                faiss.write_index(self._faiss_index, str(self._faiss_index_path))
                logger.info("Saved FAISS index to %s", self._faiss_index_path)
            except Exception as e:
                logger.warning("Could not save FAISS index: %s", e)

        # Save BM25 index
        if self._bm25_index is not None:
            try:
                with open(self._bm25_index_path, "wb") as fh:
                    pickle.dump(self._bm25_index, fh)
                logger.info("Saved BM25 index to %s", self._bm25_index_path)
            except Exception as e:
                logger.warning("Could not save BM25 index: %s", e)

        # Save CWE data
        with open(self._cwe_data_path, "w", encoding="utf-8") as fh:
            json.dump(list(self._cwe_map.values()), fh, indent=2)
        logger.info("Saved CWE data to %s", self._cwe_data_path)

        # Save CVE data
        with open(self._cve_data_path, "w", encoding="utf-8") as fh:
            json.dump(self._cve_entries, fh, indent=2)
        logger.info("Saved CVE data to %s", self._cve_data_path)

        # Save document corpus
        doc_path = self._cwe_data_path.parent / "documents.json"
        with open(doc_path, "w", encoding="utf-8") as fh:
            json.dump(self._documents, fh, indent=2)

        # Save metadata
        metadata = {
            "total_documents": len(self._documents),
            "total_cwes": len(self._cwe_map),
            "total_cves": len(self._cve_entries),
            "built_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(self._metadata_path, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2)

        logger.info(
            "Knowledge base saved: %d documents (%d CWEs, %d CVEs)",
            len(self._documents), len(self._cwe_map), len(self._cve_entries),
        )

    def _try_load(self) -> None:
        """Attempt to load pre-built indexes from disk."""
        # Load CWE data
        if self._cwe_data_path.exists():
            try:
                with open(self._cwe_data_path, "r", encoding="utf-8") as fh:
                    cwe_list = json.load(fh)
                self._cwe_map = {e["id"]: e for e in cwe_list}
                logger.info("Loaded %d CWE entries from disk", len(self._cwe_map))
            except Exception as e:
                logger.debug("Could not load CWE data: %s", e)

        # Load CVE data
        if self._cve_data_path.exists():
            try:
                with open(self._cve_data_path, "r", encoding="utf-8") as fh:
                    self._cve_entries = json.load(fh)
                logger.info("Loaded %d CVE entries from disk", len(self._cve_entries))
            except Exception as e:
                logger.debug("Could not load CVE data: %s", e)

        # Load document corpus
        doc_path = self._cwe_data_path.parent / "documents.json"
        if doc_path.exists():
            try:
                with open(doc_path, "r", encoding="utf-8") as fh:
                    self._documents = json.load(fh)
                logger.info("Loaded %d documents from disk", len(self._documents))
            except Exception as e:
                logger.debug("Could not load documents: %s", e)

        # Load FAISS index
        if self._faiss_index_path.exists():
            try:
                import faiss  # type: ignore[import-untyped]
                self._faiss_index = faiss.read_index(str(self._faiss_index_path))
                logger.info(
                    "Loaded FAISS index: %d vectors", self._faiss_index.ntotal
                )
            except ImportError:
                logger.debug("FAISS not available; skipping index load")
            except Exception as e:
                logger.debug("Could not load FAISS index: %s", e)

        # Load BM25 index
        if self._bm25_index_path.exists():
            try:
                with open(self._bm25_index_path, "rb") as fh:
                    self._bm25_index = pickle.load(fh)  # noqa: S301
                logger.info("Loaded BM25 index from disk")
            except Exception as e:
                logger.debug("Could not load BM25 index: %s", e)

    # ------------------------------------------------------------------
    # Embedding & tokenisation helpers
    # ------------------------------------------------------------------

    def _get_embeddings(self, texts: list[str]) -> np.ndarray:
        """Generate embeddings, caching the sentence-transformer model.

        Args:
            texts: Strings to embed.

        Returns:
            Float32 array of shape ``(len(texts), 384)``.
        """
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
                self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
            except ImportError:
                logger.warning(
                    "sentence-transformers not installed; using random embeddings"
                )
                return np.random.randn(len(texts), 384).astype(np.float32)

        embeddings = self._embedder.encode(
            texts,
            show_progress_bar=len(texts) > 100,
            convert_to_numpy=True,
            batch_size=64,
        )
        return embeddings.astype(np.float32)

    @staticmethod
    def _tokenise(text: str) -> list[str]:
        """Simple whitespace + punctuation tokeniser for BM25.

        Converts to lowercase, strips punctuation, and splits on
        whitespace.  Adequate for CWE/CVE text where domain-specific
        tokenisation adds little value over simple splitting.

        Args:
            text: Input string.

        Returns:
            List of lowercase token strings.
        """
        import re
        text = text.lower()
        text = re.sub(r"[^\w\s-]", " ", text)
        tokens = text.split()
        # Remove very short tokens (noise) but keep CWE/CVE identifiers
        return [t for t in tokens if len(t) >= 2]


# Import here to avoid circular; only used in _save().
from datetime import timezone
