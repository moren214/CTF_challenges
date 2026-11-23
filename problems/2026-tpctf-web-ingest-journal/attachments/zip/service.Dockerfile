FROM php:8.5.11-apache
COPY php.ini /usr/local/etc/php/conf.d/zz-journal.ini
COPY apache.conf /etc/apache2/conf-enabled/zz-journal.conf
COPY public/ /var/www/html/
RUN a2enmod sed \
    && mkdir -p /var/www/html/publish/receipts/daily/open \
    && chmod 1777 /var/www/html/publish/receipts/daily/open \
    && ln -s /answers/flag /flag
EXPOSE 80
