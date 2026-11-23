FROM php:8.5.11-apache

# Deployment profile: a single maintenance worker, the relay's runtime
# diagnostics, and the courier console under the default document root.
COPY apache/mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY apache/zz-relic.conf /etc/apache2/conf-enabled/zz-relic.conf
COPY php/zz-relic.ini /usr/local/etc/php/conf.d/zz-relic.ini

COPY html/ /var/www/html/
COPY relic-lib/ /var/www/relic-lib/
COPY entrypoint.sh /usr/local/bin/relic-entrypoint.sh

RUN chmod 0755 /usr/local/bin/relic-entrypoint.sh \
 && rm -f /var/www/html/index.html /var/www/html/index.htm
RUN a2dismod mpm_event >/dev/null 2>&1 || true
RUN a2enmod mpm_prefork

EXPOSE 80
CMD ["/usr/local/bin/relic-entrypoint.sh"]
