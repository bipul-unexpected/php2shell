# Vulnerable branch: 8.2.34 (< 8.2.35). Override PHP_TAG if the exact tag is
# unavailable in your mirror: 8.2.30 and 8.2.33 are also in range.
ARG PHP_TAG=8.2.34
FROM php:${PHP_TAG}-fpm

COPY php/php.ini /usr/local/etc/php/conf.d/99-php2shell.ini
RUN mkdir -p /tmp/sess && chown www-data:www-data /tmp/sess && chmod 1733 /tmp/sess

WORKDIR /var/www/html
EXPOSE 9000
