ARG APACHE_VERSION=2.4
FROM httpd:${APACHE_VERSION}

RUN apt-get update && \
    apt-get install -y apache2-dev gcc make curl

WORKDIR /usr/local/src

COPY mod_antibot.c .

RUN apxs -c -i mod_antibot.c && \
    install -c .libs/mod_antibot.so /usr/local/apache2/modules/mod_antibot.so

RUN echo 'IncludeOptional /etc/apache2/conf.d/antibot.conf' >> /usr/local/apache2/conf/httpd.conf

HEALTHCHECK CMD curl -f http://localhost/
