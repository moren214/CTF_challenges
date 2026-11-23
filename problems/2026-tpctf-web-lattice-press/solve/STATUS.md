# Lattice Press — status (2026-11-22 19:30)

## What works (reproducible)

Client: `lattice_press/lp.py` (HTTP + cookie jar). Tunnel: WSL Ubuntu-22.04,
`wg-quick up lat` with the instance's `vpn-config` (DNS line stripped), then
`LP_HOST=<services[0].host> LP_CONNECT=172.16.<x>.2 python3 -u <script>`.

Standard flow (all requests must carry the cookie jar):

1. `POST /api/plans {"slug":"demo","body":"HELLO\n"}` → 200
2. `POST /api/plans/demo/stage {}` → 200 `{"stage_token": "...", "lane":"81af14c1"}`
3. `POST /api/plans/demo/attach {"stage_token": tok}` → 200, sets
   `Set-Cookie: lattice_plan=demo; path=/; HttpOnly; SameSite=Lax` (required!)
4. `POST /api/plans/demo/verify {}` → 200
   `{"verified":true,"checksum_ok":true,"version_supported":true,"lane_ready":true,"warm_bytes":<len>}`
5. `GET /api/plans/demo/preview` → 200
   `{"slug":"demo","lane":"81af14c1","html":"<div class=\"lp-frame\">HELLO\n</div>","rendered_at":...}`

Without the cookie from step 3, verify always answers 422
`"The plan is not warm on this lane; attach it to the lane first."`

## Confirmed behaviours / bugs

* The preview renders the **lane's warm buffer for any valid slug** (preview of a
  never-staged plan shows the last warmed plan's body). The URL slug only has to
  exist in the register.
* The warm buffer is cleared by `stage` and by `POST /api/runtime/lane/refresh`;
  `warm_bytes` equals the plan body length.
* `{{row}}` and every other `{{...}}`/`${...}` placeholder is rendered literally
  for our own plans and for the three seeded plans.
* Any `<?` in a plan body makes `verify` fail with
  "Plan text may not contain markup blocks."; `<?` hidden after a NUL byte is
  still detected, and `<%`, `<script language="php">`, HTML entities
  (`&lt;?php`) are not decoded, so no PHP include is reachable.
* Cookie `lattice_plan`/`lattice_lane`, headers `X-Render-Row/X-Pinned/
  X-Collector-*/User-Agent`, query params (`?row=`, `?pinned=`...) do not change
  the rendered output.
* `POST /api/runtime/lane/refresh` clears the review state and then the lane
  answers `409 {"code":"lane_busy","message":"The lane is being rotated for
  maintenance; retry later."}` for stage/attach forever (instance must be
  rebuilt). `POST /api/plans/<slug>/preview-legacy` has the same effect.
  An `attach` with a stale token (409 `stage_stale`) also rotates the lane.
* `X-Render-Window` sizes an allocation (1 GiB → 500 / worker wedge,
  ~128 MiB = PHP memory limit) but does not truncate, leak or overflow the
  rendered body.
* The register (`/var/lib/lattice`) **persists across instance rebuilds**:
  plans created on earlier instances (123, vv3..vv5, p-6d7f7c8d) are visible on
  a freshly created instance.
* Only the 12 documented routes exist; ~70 extra paths and ~430 query
  parameters return no additional data.

## Blocked

The operator's pinned value never appears: `{{row}}` is not substituted, no
hidden plan is listed or guessable, and the instance state file
(`/var/lib/lattice/instance`) is not readable through any route found.

## Next hypotheses

1. The warm buffer is the only mutable render input; if the operator's
   statement was warmed before hand-over it is not in the cache of a rebuilt
   instance (warm_bytes 0) — check whether a *stale* warm buffer can be revived
   after `refresh` (history rebuild) on a lane that still answers.
2. The `{{row}}` substitution may only run in the planrt template mode observed
   once at 10:50 (right after a 1 GiB OOM), where `${row}` was stored as empty.
   Reproduce that OOM state on a disposable lane and create plans with
   `${row}`/`${pinned}` to see whether the pin table is populated then.
3. Look for the pinned plan by slug oracle (`GET /api/plans/<slug>` 200 vs 404)
   with a larger generated wordlist around "pinned/operator/statement".
