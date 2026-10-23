ARG PHP_TAG=8.2.34
FROM php:${PHP_TAG}-apache

COPY php/php.ini /usr/local/etc/php/conf.d/99-php2shell.ini
RUN mkdir -p /tmp/sess && chown www-data:www-data /tmp/sess && chmod 1733 /tmp/sess

WORKDIR /var/www/html
EXPOSE 80
