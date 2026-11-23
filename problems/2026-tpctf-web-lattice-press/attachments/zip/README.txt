Lattice Press workspace

The app image is built from the sources in services/app:

  services/app/public        request router and static readiness file
  services/app/ext/planrt    request-time plan runtime (lane cache, prefetch
                             window, manifest review state, render entry)
  services/app/conf          Apache lane settings and PHP runtime settings

Build and run locally:

  docker compose build
  docker compose up -d
  docker compose exec app curl -fsS http://localhost/healthz

The register lives under /var/lib/lattice; the render lanes read their staged
plan from /var/lib/lattice/staging/<lane>.plan. Lane identifiers appear in the
X-Runtime-Lane response header and in /api/diagnostics.

The seeded register keeps a few operator plans (ops-history-2024,
ops-carried-2023, ops-quarterly-2025) whose notes describe the hand-over
routine for older queues.

Maintenance actions

  POST /api/runtime/lane/refresh
        rebuild the prefetch cache of the lane that serves the call; the
        staged plan for that lane is cleared and a maintenance entry is
        appended to /var/lib/lattice/history.

  POST /api/plans/<slug>/preview-legacy
        page a plan through the legacy renderer used for historical
        registers. It returns a plain page of the statement text and records
        the pass in /var/lib/lattice/history.

An instance keeps its workspace maintenance state under
/var/lib/lattice/instance; a different deployment starts from its own state.

Automated collectors identify themselves as lattice-collector/1.4. Lane
budgets are metered per collector group; when a lane is busy the call returns
429 with a retry hint.
