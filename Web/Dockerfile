FROM ubuntu:latest


RUN apt-get update && \
    apt-get install -y apache2

RUN apt-get install curl
RUN apt-get install sudo

RUN apt-get install -y supervisor
RUN apt-get install net-tools


RUN curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.10.2-amd64.deb
RUN sudo dpkg -i filebeat-8.10.2-amd64.deb

RUN chmod 777 /etc/init.d
RUN chmod 777 /var/log/apache2/*.log
RUN chmod 777 /var/www/html

COPY ["filebeat.yml", "/etc/filebeat/filebeat.yml"]
COPY ["initFilebeat", "/etc/init.d/initFilebeat"]

RUN filebeat modules enable apache


EXPOSE 80

CMD ["apache2ctl", "-D", "FOREGROUND"]
