#!/bin/sh
# Wired Relic container start-up.
# The relay keeps the operator's pinned ledger entry outside the public
# document root, readable by the console account only through the deep
# archival location prepared here. The console's signing material is
# generated for this instance, never baked into the image.
set -eu

install -d -m 0755 /var/www/private
install -d -m 0755 /var/lib/relic/depot/chain/unit

if [ -f /answers/flag ]; then
    cp /answers/flag /var/lib/relic/depot/chain/unit/ledger
    chmod 0644 /var/lib/relic/depot/chain/unit/ledger
fi

head -c 32 /dev/urandom | base64 | tr -d '\n' > /var/www/private/console.key
chmod 0644 /var/www/private/console.key

exec apache2-foreground
