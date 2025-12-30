FROM mysql:8

ENV MYSQL_ROOT_PASSWORD universalpassword
ENV MYSQL_HOST localhost
ENV MYSQL_TCP_PORT 3306

EXPOSE 3306

ADD ./init.sql /docker-entrypoint-initdb.d