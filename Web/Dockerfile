FROM ubuntu:latest


RUN apt-get update 

ENV TZ=Asia/Singapore
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get install -y apache2 php libapache2-mod-php

RUN apt-get install curl
RUN apt-get install sudo

RUN apt-get install -y systemd #added
RUN apt-get install -y systemctl #added

RUN apt-get install -y nano #added
RUN apt-get install -y tcpflow #added


RUN apt-get -y install rsyslog


RUN apt-get install -y supervisor
RUN apt-get install net-tools
RUN sudo usermod -aG sudo,adm,root www-data
RUN echo "www-data ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers

RUN curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.10.2-amd64.deb
RUN sudo dpkg -i filebeat-8.10.2-amd64.deb

RUN chmod 777 /etc/init.d
RUN chmod 777 /var/log/apache2/*.log
RUN chmod 777 /var/www/html

RUN cd /var/log
RUN mkdir tcplog
RUN chgrp adm tcplog

RUN mkdir /var/www/html/upload
RUN chmod -R 755 /var/www/html/upload

COPY ["filebeat.yml", "/etc/filebeat/filebeat.yml"]
COPY ["initFilebeat", "/etc/init.d/initFilebeat"]

COPY ["tcp_logging.sh", "/var/log/tcplog/tcp_logging.sh"] #added
COPY ["tcp_logging.service", "etc/systemd/system/tcp_logging.service"] #added

RUN chmod 777 /var/log/tcplog/tcp_logging.sh #added
RUN chmod 777 /etc/systemd/system/tcp_logging.service #added


RUN chmod go-w /etc/filebeat/filebeat.yml #added
RUN filebeat modules enable apache

RUN echo "[supervisord]" > /etc/supervisord.conf && \
    echo "nodaemon=true" >> /etc/supervisord.conf && \
    echo "" >> /etc/supervisord.conf && \
    echo "[program:apache2]" >> /etc/supervisord.conf && \
    echo "command=apache2ctl -D FOREGROUND" >> /etc/supervisord.conf && \
    echo "autorestart=true" >> /etc/supervisord.conf && \
    echo "" >> /etc/supervisord.conf && \
    echo "[program:filebeat]" >> /etc/supervisord.conf && \
    echo "command=filebeat -e -c /etc/filebeat/filebeat.yml" >> /etc/supervisord.conf && \
    echo "autorestart=true" >> /etc/supervisord.conf && \
    echo "" >> /etc/supervisord.conf && \
    echo "[program:tcp_logging]" >> /etc/supervisord.conf && \
    echo "command=/var/log/tcplog/tcp_logging.sh" >> /etc/supervisord.conf   && \
    echo "autorestart=true" >> /etc/supervisord.conf

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

