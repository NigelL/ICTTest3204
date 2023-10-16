FROM ubuntu:latest


RUN apt-get update && \
    apt-get install -y apache2

RUN apt-get install curl
RUN apt-get install sudo

RUN apt-get install -y supervisor
RUN apt-get install net-tools
RUN apt-get -y install python3.6

RUN mkdir -m 777 dev_files && touch dev_files/secret.py
RUN echo '#!/usr/bin/python3' > dev_files/secret.py
RUN echo 'import os\n' >> dev_files/secret.py
RUN echo 'os.system("/bin/bash")\n' >> dev_files/secret.py

RUN touch .PLS_DELETE_THIS.txt
RUN echo "admin" > .PLS_DELETE_THIS.txt
RUN echo "changeme" >> .PLS_DELETE_THIS.txt


RUN curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.10.2-amd64.deb
RUN sudo dpkg -i filebeat-8.10.2-amd64.deb

RUN chmod 777 /etc/init.d
RUN chmod 777 /var/log/apache2/*.log
RUN chmod -R 777 /var/www

ARG USER=admin
ARG PASS="changeme"
RUN useradd -m -s /bin/bash $USER && echo "$USER:$PASS" | chpasswd
RUN usermod -aG root admin

COPY ["filebeat.yml", "/etc/filebeat/filebeat.yml"]
COPY ["initFilebeat", "/etc/init.d/initFilebeat"]

RUN chmod go-w /etc/filebeat/filebeat.yml

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
    echo "autorestart=true" >> /etc/supervisord.conf

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

