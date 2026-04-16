# AssetPortal

Internal file management portal — upload, download, and verify assets.

## Vulnerabilities

| CWE | Location | Description |
|-----|----------|-------------|
| CWE-434 | app.py:upload_asset, storage.py:save_file | Unrestricted upload — no file type/extension check |
| CWE-22 | storage.py:save_file, resolve_path | Path traversal — filename joined to UPLOAD_DIR without sanitization |
| CWE-327 | crypto.py:checksum, hash_password | Weak crypto — MD5 for integrity + password hashing |
| CWE-798 | app.py:ADMIN_TOKEN | Hardcoded admin bearer token |

## Inter-procedural flow

`app.py:upload_asset` → `storage.save_file(f.filename, data)` — taint from `request.files["file"].filename` into `os.path.join`.
`app.py:verify_asset` → `storage.resolve_path(filename)` → `open(full_path)` — path traversal to read arbitrary files.
