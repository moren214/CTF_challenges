# Pinned QuickJS III — player notes

The service is a TCP JSON-Lines JavaScript evaluator:

```text
-> {"code":"1+1"}
<- {"ok":true,"result":2}
```

A fresh worker is created for each connection. The worker holds one
per-instance flag in its environment as `QJS_CTF_FLAG=<flag>`; normal
JavaScript APIs expose no file, process, module, or network access.

## Files

- `quickjs-base-bundle.tar.gz` — the public QuickJS 2026-06-04 build
  bundle: adapter, runner, source tree, build files and the protocol notes.
- `patch.diff` — the production patch applied to this instance's QuickJS
  source, relative to the public bundle.

## Goal

Recover the per-instance flag from the running worker and submit it exactly
as returned. The flag is not in either attachment; the patch is the only
source-level delta between the public bundle and the running build.
