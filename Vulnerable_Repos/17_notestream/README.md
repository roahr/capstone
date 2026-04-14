# NoteStream

Collaborative note-taking REST API (Node/Express/MongoDB).

## Vulnerabilities

| CWE | Location | Description |
|-----|----------|-------------|
| CWE-943 | routes/notes.js:search,export; routes/users.js:login,profile | NoSQL injection — raw req.query/body objects passed into MongoDB queries; $where template literal |
| CWE-1321 | lib/utils.js:mergeOptions | Prototype pollution — recursive merge without __proto__ guard |
| CWE-614 | server.js:session | Insecure cookie — `secure: false`, `httpOnly: false` |
| CWE-532 | routes/users.js:login; server.js:health | Sensitive log — password and session data written to logger |

## Inter-procedural flow

`routes/notes.js:GET /` → `utils.mergeOptions({}, req.query.filter)` — taint from query into recursive merge.
`routes/notes.js:export` → MongoDB `$where` with `note.author` (from DB, originally from user-supplied login).
