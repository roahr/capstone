"""
CWE Catalog Indexer for the SEC-C RAG knowledge base.

Downloads the MITRE CWE catalog, parses the XML into structured entries,
and builds a FAISS vector index from CWE descriptions for semantic search.
Each CWE entry includes its ID, name, description, detection methods,
and mitigations -- everything the dual-agent LLM needs for contextual
vulnerability assessment.
"""

from __future__ import annotations

import io
import logging
import os
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

import httpx
import numpy as np

logger = logging.getLogger(__name__)

# Official MITRE CWE catalog download URL (latest XML archive).
CWE_CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# XML namespaces used by the CWE schema (v6 and v7).
_NS_CANDIDATES = [
    {"cwe": "http://cwe.mitre.org/cwe-7"},
    {"cwe": "http://cwe.mitre.org/cwe-6"},
]
_NS = _NS_CANDIDATES[0]  # Default to latest; auto-detected in parse_cwe_xml


class CWEIndexer:
    """Downloads, parses, and indexes the MITRE CWE catalog.

    The indexer operates in two phases:

    1. **Download & Parse** -- fetches the latest CWE XML catalog from MITRE,
       extracts it, and converts each weakness entry into a structured dict.
    2. **Index** -- encodes CWE descriptions into dense vectors using
       sentence-transformers and builds a FAISS index for fast semantic
       retrieval.

    The resulting index is saved to disk so subsequent runs can skip the
    expensive embedding step.
    """

    def __init__(self) -> None:
        self._cwe_map: dict[str, dict[str, Any]] = {}
        self._active_ns = _NS_CANDIDATES[0]  # Auto-detected during parse

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def download_cwe_catalog(self, output_dir: str | Path) -> Path:
        """Download the latest CWE catalog XML from MITRE.

        Args:
            output_dir: Directory where the extracted XML file will be
                written.  Created if it does not exist.

        Returns:
            Path to the extracted XML file on disk.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Downloading CWE catalog from %s", CWE_CATALOG_URL)

        with httpx.Client(timeout=120, follow_redirects=True) as client:
            resp = client.get(CWE_CATALOG_URL)
            resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
            if not xml_names:
                raise RuntimeError("No XML file found in CWE catalog archive")

            xml_name = xml_names[0]
            zf.extract(xml_name, path=str(output_dir))
            xml_path = output_dir / xml_name

        logger.info("CWE catalog extracted to %s", xml_path)
        return xml_path

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_cwe_xml(self, xml_path: str | Path) -> list[dict[str, Any]]:
        """Parse a CWE XML catalog into a list of structured dicts.

        Each dict contains:
        - ``id``: CWE identifier string (e.g. ``"CWE-79"``).
        - ``name``: Human-readable weakness name.
        - ``description``: Extended natural-language description.
        - ``detection_methods``: List of detection method descriptions.
        - ``mitigations``: List of mitigation descriptions.

        Args:
            xml_path: Path to the unzipped CWE XML file.

        Returns:
            List of parsed CWE entry dicts.
        """
        xml_path = Path(xml_path)
        logger.info("Parsing CWE XML: %s", xml_path)

        tree = ET.parse(str(xml_path))
        root = tree.getroot()

        entries: list[dict[str, Any]] = []

        # Auto-detect namespace from root tag
        active_ns = _NS
        for ns_candidate in _NS_CANDIDATES:
            test = root.find("cwe:Weaknesses", ns_candidate)
            if test is not None:
                active_ns = ns_candidate
                logger.info("Detected CWE namespace: %s", ns_candidate["cwe"])
                break

        # The catalog nests weaknesses under <Weaknesses>/<Weakness>.
        weaknesses_elem = root.find("cwe:Weaknesses", active_ns)
        if weaknesses_elem is None:
            logger.warning("No <Weaknesses> element found in CWE XML")
            return entries

        self._active_ns = active_ns
        for weakness in weaknesses_elem.findall("cwe:Weakness", active_ns):
            entry = self._parse_weakness_element(weakness)
            if entry:
                entries.append(entry)
                self._cwe_map[entry["id"]] = entry

        logger.info("Parsed %d CWE entries from catalog", len(entries))
        return entries

    def _parse_weakness_element(
        self, elem: ET.Element
    ) -> dict[str, Any] | None:
        """Extract structured data from a single <Weakness> element."""
        cwe_id_num = elem.get("ID")
        if cwe_id_num is None:
            return None

        cwe_id = f"CWE-{cwe_id_num}"
        name = elem.get("Name", "")

        # Description
        desc_elem = elem.find("cwe:Description", self._active_ns)
        description = (desc_elem.text or "").strip() if desc_elem is not None else ""

        # Extended Description
        ext_desc_elem = elem.find("cwe:Extended_Description", self._active_ns)
        if ext_desc_elem is not None:
            ext_text = self._extract_text(ext_desc_elem)
            if ext_text:
                description = f"{description} {ext_text}".strip()

        # Detection Methods
        detection_methods: list[str] = []
        det_elem = elem.find("cwe:Detection_Methods", self._active_ns)
        if det_elem is not None:
            for method in det_elem.findall("cwe:Detection_Method", self._active_ns):
                method_desc = method.find("cwe:Description", self._active_ns)
                if method_desc is not None:
                    text = self._extract_text(method_desc)
                    if text:
                        detection_methods.append(text)

        # Mitigations
        mitigations: list[str] = []
        mit_elem = elem.find("cwe:Potential_Mitigations", self._active_ns)
        if mit_elem is not None:
            for mitigation in mit_elem.findall("cwe:Mitigation", self._active_ns):
                mit_desc = mitigation.find("cwe:Description", self._active_ns)
                if mit_desc is not None:
                    text = self._extract_text(mit_desc)
                    if text:
                        mitigations.append(text)

        # Related weaknesses (parent/child CWE references)
        related: list[str] = []
        rel_elem = elem.find("cwe:Related_Weaknesses", self._active_ns)
        if rel_elem is not None:
            for rw in rel_elem.findall("cwe:Related_Weakness", self._active_ns):
                rw_id = rw.get("CWE_ID")
                if rw_id:
                    related.append(f"CWE-{rw_id}")

        # Common Consequences
        consequences: list[str] = []
        cons_elem = elem.find("cwe:Common_Consequences", self._active_ns)
        if cons_elem is not None:
            for consequence in cons_elem.findall("cwe:Consequence", self._active_ns):
                scope = consequence.find("cwe:Scope", self._active_ns)
                impact = consequence.find("cwe:Impact", self._active_ns)
                parts = []
                if scope is not None and scope.text:
                    parts.append(scope.text.strip())
                if impact is not None and impact.text:
                    parts.append(impact.text.strip())
                if parts:
                    consequences.append(": ".join(parts))

        return {
            "id": cwe_id,
            "name": name,
            "description": description,
            "detection_methods": detection_methods,
            "mitigations": mitigations,
            "related_weaknesses": related,
            "consequences": consequences,
        }

    @staticmethod
    def _extract_text(elem: ET.Element) -> str:
        """Recursively extract all text content from an XML element."""
        parts: list[str] = []
        if elem.text:
            parts.append(elem.text.strip())
        for child in elem:
            child_text = CWEIndexer._extract_text(child)
            if child_text:
                parts.append(child_text)
            if child.tail:
                parts.append(child.tail.strip())
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Index building
    # ------------------------------------------------------------------

    def build_index(
        self, cwe_dir: str | Path
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Build a FAISS index from parsed CWE entries on disk.

        Looks for XML files in *cwe_dir*, parses them, generates
        sentence-transformer embeddings, and constructs a flat FAISS
        index using cosine similarity.

        Args:
            cwe_dir: Directory containing the CWE XML catalog file.

        Returns:
            A tuple ``(faiss_index, metadata_list)`` where *metadata_list*
            is aligned with the FAISS index rows so that index position ``i``
            corresponds to ``metadata_list[i]``.
        """
        cwe_dir = Path(cwe_dir)

        # Find the XML file
        xml_files = list(cwe_dir.glob("*.xml"))
        if not xml_files:
            raise FileNotFoundError(
                f"No CWE XML file found in {cwe_dir}. "
                "Run download_cwe_catalog() first."
            )

        entries = self.parse_cwe_xml(xml_files[0])
        if not entries:
            raise ValueError("No CWE entries parsed from XML")

        # Build description texts for embedding
        texts = []
        for entry in entries:
            text = f"{entry['id']} {entry['name']}: {entry['description']}"
            texts.append(text)

        # Generate embeddings
        embeddings = self._embed_texts(texts)

        # Build FAISS index
        try:
            import faiss  # type: ignore[import-untyped]

            dim = embeddings.shape[1]
            index = faiss.IndexFlatIP(dim)  # Inner product (cosine on normalised vecs)
            faiss.normalize_L2(embeddings)
            index.add(embeddings)

            logger.info(
                "Built FAISS index with %d CWE entries (dim=%d)",
                index.ntotal, dim,
            )
            return index, entries

        except ImportError:
            logger.warning(
                "FAISS not available; returning raw embeddings array instead. "
                "Install faiss-cpu for proper vector search."
            )
            return embeddings, entries

    # ------------------------------------------------------------------
    # Direct lookup
    # ------------------------------------------------------------------

    def get_cwe_info(self, cwe_id: str) -> dict[str, Any] | None:
        """Look up a CWE entry by its identifier.

        Args:
            cwe_id: CWE identifier string, e.g. ``"CWE-79"`` or ``"79"``.

        Returns:
            The parsed CWE dict, or ``None`` if the ID is not in the loaded
            catalog.
        """
        # Normalise the ID format
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        cwe_id = cwe_id.upper()

        return self._cwe_map.get(cwe_id)

    # ------------------------------------------------------------------
    # Embedding helper
    # ------------------------------------------------------------------

    @staticmethod
    def _embed_texts(texts: list[str]) -> np.ndarray:
        """Encode texts to dense vectors using sentence-transformers.

        Uses the ``all-MiniLM-L6-v2`` model (22M params, 384-dim output),
        which is small, fast, and freely available.

        Args:
            texts: List of text strings to encode.

        Returns:
            NumPy array of shape ``(len(texts), 384)`` with float32 vectors.
        """
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

            model = SentenceTransformer("all-MiniLM-L6-v2")
            embeddings = model.encode(
                texts,
                show_progress_bar=True,
                convert_to_numpy=True,
                batch_size=64,
            )
            return embeddings.astype(np.float32)

        except ImportError:
            logger.warning(
                "sentence-transformers not installed. "
                "Using random embeddings as fallback (not suitable for production)."
            )
            return np.random.randn(len(texts), 384).astype(np.float32)
