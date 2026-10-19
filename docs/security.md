# Threat model and observed boundary

Assets: bounded public aggregates, catalog metadata and audit accountability. The model/client is untrusted; the stdio host, OS owner, launch arguments and source files are trusted. No confidential data is bundled.

Capabilities are deliberately small. A model cannot submit SQL, a filesystem path, a network URL or an identity claim to become an analyst. Reading the internal observations table, writes, extension loading and ATTACH are denied at the SQLite connection as defense in depth. Those checks do not protect against the trusted OS owner opening the file independently.

Injected catalog instructions are still untrusted text. A test inserts a malicious instruction into the description, reads it through MCP, then confirms a catalog-role aggregate request is denied. This tests permission separation, not a language model's resistance to prompt injection. A consumer must preserve trust labels and independently enforce its other tools.

Audit middleware surrounds SDK validation and lookup. Tool/schema failures are retained, argument values are hashed, and the response is withheld if the audit append fails. Hash chaining detects edits in retained entries, but without an external checkpoint cannot prove completeness or prevent full-chain replacement/truncation. One process owns one log; multi-process append coordination is not implemented.

No HTTP server, remote identity verification, token passthrough or third-party API exists. Remote deployment needs a separate authorization design; do not substitute client-supplied role metadata for identity.

Primary references: [official MCP SDK](https://py.sdk.modelcontextprotocol.io/), [MCP security practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices), [SQLite authorizer](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.set_authorizer). Consulted 2026-10-19; no tutorial implementation copied.
