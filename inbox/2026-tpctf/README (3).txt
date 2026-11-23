quickjs-base-bundle.tar.gz
    Pinned base sources for the evaluation service: QuickJS 2026-06-04,
    the C worker runner, the TCP adapter, build files and protocol notes.
    This archive is the unpatched base.  The provenance and build manifest
    inside it describe that base, not the patched build the service runs.

patch.diff
    The exact change applied to the engine source for the service.  Apply
    it from the extracted bundle root:

        tar xzf quickjs-base-bundle.tar.gz -C bundle
        cd bundle
        patch -p1 < /path/to/patch.diff
        make runner

Service protocol
    TCP, JSON Lines, port 8000.  One request per line:

        {"code": "<JavaScript source>"}

    One reply per line, either {"ok": true, "result": ...} or
    {"ok": false, "error": {...}}.  Runtime state is kept for the life of
    a TCP connection.
