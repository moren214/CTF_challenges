Wired Relic — deployed relay source
===================================

This archive is the relay's deployed source and configuration, published so
the deployment can be audited rather than guessed at:

  Dockerfile              image build (single maintenance worker profile)
  entrypoint.sh           container start-up and archival-store preparation
  apache/mpm_prefork.conf worker/lifecycle settings
  apache/zz-relic.conf    server defaults
  php/zz-relic.ini        relay runtime profile
  html/                   public console, scratch area, landing and bay
  relic-lib/lib.php       console signing helpers (outside the document root)

The running node uses exactly these files. The platform's per-instance
ledger entry is supplied to the node at start-up; it is not part of this
archive.
