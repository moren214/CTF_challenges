# Engine evaluation service

This bundle is the full source for the pinned QuickJS 2026-06-04 baseline,
including the TCP adapter, the minimal C host, and the build metadata.
`patch.diff` is the complete set of engine-core changes applied when
building the online worker. The service protocol is JSON Lines over TCP:
send one request per line as `{"code":"<JavaScript source>"}` and read
one JSON reply.
