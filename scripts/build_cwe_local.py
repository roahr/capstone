"""Build CWE + RAG knowledge base from built-in data (no downloads needed)."""
import json
from pathlib import Path

CWE_DATA = {
    "CWE-78": {"name": "OS Command Injection", "desc": "The software constructs OS commands using externally-influenced input without neutralizing special elements.", "mitigations": ["Use parameterized APIs", "Input validation with allowlists", "Avoid shell=True"], "detection": "Taint from user input to os.system(), subprocess with shell=True"},
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "desc": "User-controllable input placed in web page output without neutralization.", "mitigations": ["HTML entity encoding", "Content Security Policy", "Auto-escaping templates"], "detection": "Taint from user input to HTML output without encoding"},
    "CWE-89": {"name": "SQL Injection", "desc": "SQL commands constructed using external input without neutralizing special elements.", "mitigations": ["Parameterized queries", "Use ORM", "Input validation"], "detection": "Taint from user input to SQL query via string concatenation"},
    "CWE-22": {"name": "Path Traversal", "desc": "External input used to construct pathname without neutralizing ../ sequences.", "mitigations": ["Canonicalize paths", "Validate within base directory", "Use chroot"], "detection": "Taint from user input to file system operations"},
    "CWE-94": {"name": "Code Injection", "desc": "Code segment constructed using external input without neutralization.", "mitigations": ["Avoid eval/exec", "Use ast.literal_eval", "Sandboxing"], "detection": "Taint from user input to eval(), exec(), compile()"},
    "CWE-95": {"name": "Eval Injection", "desc": "Input inserted into dynamically evaluated expression without neutralization.", "mitigations": ["Never pass user input to eval()", "Use ast.literal_eval()"], "detection": "Direct user input to eval() or exec()"},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "desc": "Untrusted data deserialized without verification, allowing arbitrary code execution.", "mitigations": ["Use JSON instead of pickle", "Cryptographic signing", "Input validation"], "detection": "Taint from user input to pickle.loads(), yaml.load()"},
    "CWE-798": {"name": "Hardcoded Credentials", "desc": "Hard-coded passwords or cryptographic keys in source code.", "mitigations": ["Use environment variables", "Secret management systems"], "detection": "Pattern matching for password/secret/key assignments"},
    "CWE-327": {"name": "Broken Cryptographic Algorithm", "desc": "Use of broken or risky cryptographic algorithms (MD5, SHA1, DES).", "mitigations": ["Use AES-256/SHA-256+", "bcrypt/scrypt for passwords"], "detection": "Pattern matching for hashlib.md5, hashlib.sha1, DES"},
    "CWE-119": {"name": "Buffer Overflow", "desc": "Operations on memory buffer reading/writing outside intended boundary.", "mitigations": ["Safe string functions", "Bounds checking"], "detection": "strcpy, strcat, sprintf, gets usage"},
    "CWE-120": {"name": "Classic Buffer Overflow", "desc": "Input buffer copied to output without size verification.", "mitigations": ["Use strncpy/strlcpy", "Check buffer sizes"], "detection": "Unbounded copy: strcpy, strcat, sprintf"},
    "CWE-134": {"name": "Format String Vulnerability", "desc": "Format string from external source passed to printf-family functions.", "mitigations": ["Always specify format string explicitly"], "detection": "User input as format argument to printf family"},
    "CWE-416": {"name": "Use After Free", "desc": "Memory referenced after being freed.", "mitigations": ["NULL after free", "Smart pointers"], "detection": "Data flow from free() to subsequent dereference"},
    "CWE-476": {"name": "NULL Pointer Dereference", "desc": "Application dereferences a pointer expected valid but is NULL.", "mitigations": ["Check before dereference", "Optional types"], "detection": "Missing null checks before pointer use"},
    "CWE-287": {"name": "Improper Authentication", "desc": "Identity claim not sufficiently verified.", "mitigations": ["Established auth frameworks", "MFA"], "detection": "Missing or bypassable authentication checks"},
    "CWE-862": {"name": "Missing Authorization", "desc": "No authorization check when accessing resource or performing action.", "mitigations": ["RBAC", "Check permissions before action"], "detection": "Sensitive operations without authorization checks"},
    "CWE-611": {"name": "XML External Entity (XXE)", "desc": "XML processed with entities resolving outside intended control.", "mitigations": ["Disable external entities", "Use defusedxml"], "detection": "XML parser without disabled external entities"},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "desc": "Server retrieves URL from user input without destination validation.", "mitigations": ["URL allowlisting", "Disable redirects"], "detection": "User input as URL in server-side requests"},
    "CWE-434": {"name": "Unrestricted File Upload", "desc": "Dangerous file types uploaded and processed.", "mitigations": ["File type validation", "Store outside web root"], "detection": "Upload handlers without type validation"},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "desc": "State-changing request not verified as intentional.", "mitigations": ["CSRF tokens", "SameSite cookies"], "detection": "State-changing ops without CSRF validation"},
    "CWE-1321": {"name": "Prototype Pollution", "desc": "Object prototype modified via user-controlled input.", "mitigations": ["Freeze prototypes", "Validate merge inputs"], "detection": "Recursive merge with user-controlled keys"},
    "CWE-90": {"name": "LDAP Injection", "desc": "LDAP query constructed with unescaped external input.", "mitigations": ["Escape LDAP special chars", "Parameterized queries"], "detection": "User input in LDAP filter construction"},
}

def main():
    # CWE catalog
    cwe_dir = Path("data/cwe")
    cwe_dir.mkdir(parents=True, exist_ok=True)

    cwe_list = []
    for cwe_id, info in CWE_DATA.items():
        cwe_list.append({
            "id": cwe_id, "name": info["name"],
            "description": info["desc"],
            "mitigations": info["mitigations"],
            "detection_methods": info["detection"],
        })

    (cwe_dir / "cwe_catalog.json").write_text(json.dumps(cwe_list, indent=2))
    print(f"  CWE catalog: {len(cwe_list)} entries -> data/cwe/cwe_catalog.json")

    # RAG corpus
    rag_dir = Path("data/rag")
    rag_dir.mkdir(parents=True, exist_ok=True)

    corpus = []
    for e in cwe_list:
        text = f"{e['id']} {e['name']} {e['description']} {' '.join(e['mitigations'])}"
        corpus.append({"id": e["id"], "text": text, "name": e["name"]})

    (rag_dir / "cwe_corpus.json").write_text(json.dumps(corpus, indent=2))
    print(f"  RAG corpus:  {len(corpus)} documents -> data/rag/cwe_corpus.json")

    # BM25 index
    try:
        from rank_bm25 import BM25Okapi
        import pickle as pkl

        tokenized = [doc["text"].lower().split() for doc in corpus]
        bm25 = BM25Okapi(tokenized)
        with open(rag_dir / "bm25_index.pkl", "wb") as f:
            pkl.dump({"bm25": bm25, "corpus": corpus}, f)
        print(f"  BM25 index:  built -> data/rag/bm25_index.pkl")
    except Exception as e:
        print(f"  BM25 index:  skipped ({e})")

    # FAISS index
    try:
        import numpy as np
        import faiss

        # Simple TF-IDF-like embeddings (no model download needed)
        vocab = {}
        for doc in corpus:
            for word in doc["text"].lower().split():
                if word not in vocab:
                    vocab[word] = len(vocab)

        dim = min(len(vocab), 256)
        vectors = np.zeros((len(corpus), dim), dtype=np.float32)
        for i, doc in enumerate(corpus):
            words = doc["text"].lower().split()
            for w in words:
                idx = vocab.get(w, 0)
                if idx < dim:
                    vectors[i, idx] += 1.0
            norm = np.linalg.norm(vectors[i])
            if norm > 0:
                vectors[i] /= norm

        index = faiss.IndexFlatIP(dim)
        index.add(vectors)
        faiss.write_index(index, str(rag_dir / "faiss_index.bin"))
        # Save metadata
        (rag_dir / "faiss_meta.json").write_text(json.dumps({
            "dim": dim, "n_vectors": len(corpus), "vocab_size": len(vocab)
        }, indent=2))
        print(f"  FAISS index: {len(corpus)} vectors (dim={dim}) -> data/rag/faiss_index.bin")
    except Exception as e:
        print(f"  FAISS index: skipped ({e})")

    print(f"\n  Done! RAG knowledge base ready.")


if __name__ == "__main__":
    print("\n  >> SEC-C RAG Knowledge Base Builder\n")
    main()
    print()
