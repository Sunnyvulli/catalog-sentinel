# Changelog

## 0.1.0 candidate - 2026-10-19
- Two read-only MCP v2 tools with fixed host role, strict inputs and SQLite authorizer.
- Audit middleware around schema/lookup handling, hashed arguments and failure-closed append.
- Actual stdio evaluation: 16 calls, 13 expected denials, unchanged database; 14 behavioral tests.
- Remote identity, cross-process audit locking and external audit anchoring remain open. Tag/release pending CI.
