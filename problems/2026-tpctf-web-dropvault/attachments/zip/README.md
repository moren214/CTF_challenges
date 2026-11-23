# DropVault — deployment bundle

Everything the running instance is made of, exactly as deployed:

```
src/                       application source, served from /var/www/html
  index.php                front page
  upload.php               multipart drop endpoint (POST) / upload form (GET)
  status.php               ops status board (live runtime settings)
  healthz.php              liveness probe
deploy/
  Dockerfile               image build (stock php:8.5.11-apache, copy-only)
  php-dropvault.ini        PHP overrides, installed as conf.d/zz-dropvault.ini
  mpm_prefork.conf         Apache prefork tuning
  docker-compose.yml       equivalent local deployment of the instance
```

## Running it locally

```sh
cd deploy
echo 'local-test-secret' > secret.txt
docker compose up --build
# the service answers on http://127.0.0.1:8080/
```

In production the operator's secret is injected by the platform at
`/answers/flag` (reachable through the `/flag` symlink) and is only readable
from the server itself. The local compose mounts `secret.txt` at the same
place so the deployment behaves identically.
