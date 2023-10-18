#!/bin/bash
while ((1)) ; do
    sudo tcpflow -p -c -i eth0 port 9000 >> /var/log/tcplog/tcpflow.log
    sleep 2
done

