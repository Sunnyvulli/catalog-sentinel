# Decisions

1. Stdio provides an actual interoperable MCP boundary without pretending to implement remote identity. The host assigns role once, outside model-controlled arguments.
2. Fixed aggregate tools avoid arbitrary-query parsing and reduce the attack surface. Losing flexible analytics is deliberate; scope expands only with a reviewed tool and a negative test.
3. Read-only SQLite plus an authorizer provide independent enforcement layers. Tool annotations describe behavior but grant no authority.
4. Middleware, rather than only handler logging, observes SDK schema and lookup rejection. Fail-closed logging trades availability for accountability.
5. Hash chaining is a local integrity check, not immutable external auditing. Argument hashes reduce raw-input retention but are not encryption and can be brute-forced for low-entropy inputs.
6. Bundled licensed historical data supports an offline run; no customer adoption, private dataset or production security certification is claimed.
