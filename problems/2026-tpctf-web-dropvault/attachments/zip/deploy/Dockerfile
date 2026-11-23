FROM php:8.5.11-apache
COPY deploy/php-dropvault.ini /usr/local/etc/php/conf.d/zz-dropvault.ini
COPY deploy/mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY src/ /var/www/html/
RUN chmod 0644 /var/www/html/*.php
RUN ln -s /answers/flag /flag
EXPOSE 80
