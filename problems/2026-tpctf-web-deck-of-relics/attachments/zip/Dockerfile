FROM php:8.5.11-apache

# Apache: the eight-attendant rota (prefork, fixed ServerLimit).
COPY apache/mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf

# PHP house rules.
COPY php/zz-app.ini /usr/local/etc/php/conf.d/zz-app.ini

# The deck itself. The gallery floor doubles as the attendants' workbench:
# it is writable by the house account (www-data) — attendants may leave
# working artifacts next to the exhibits while handling a delivery.
COPY public/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html && chmod 755 /var/www/html

# Per-instance answer lands here (flag-rotator sidecar), read at runtime only.
RUN ln -s /answers/flag /flag

EXPOSE 80
