FROM php:8.5.11-apache
COPY conf/hardening.ini /usr/local/etc/php/conf.d/zz-hardening.ini
COPY conf/prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY site/memtrace.conf /etc/apache2/sites-available/000-default.conf
COPY public/ /v/
RUN a2enmod rewrite && chmod 1777 /v && ln -s /answers/flag /f
EXPOSE 80
