# AuthGateway

SSO and auth delegation service with LDAP backend.

## Vulnerabilities

| CWE | Location | Description |
|-----|----------|-------------|
| CWE-90 | ldap_auth.py:authenticate | LDAP injection — username inserted into filter without escaping |
| CWE-287 | token_service.py:verify; app.py:impersonate | Algorithm confusion (alg=none accepted); admin endpoint with no authz check |
| CWE-327 | crypto: MD5 for password hashing, HMAC-MD5 for token signing | Weak crypto throughout |
| CWE-601 | app.py:login | Open redirect — `next` param from POST body not validated |
| CWE-798 | app.py:secret_key; token_service.py:SIGNING_SECRET | Hardcoded Flask secret and JWT signing key |

## Inter-procedural flow

`app.py:login` → `ldap_auth.authenticate(username, password)` → LDAP filter construction — taint from request JSON across 2 files.
`app.py:verify_token` → `token_service.verify(token)` → algorithm check — exploitable with crafted JWT header.
