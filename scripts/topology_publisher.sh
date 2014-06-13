#!/usr/bin/env bash

pidfile=$1
if [ -z "$pidfile" ]; then
    pidfile=topology-publisher.pid
fi
/opt/topology_publisher/bin/topology_publisher.py &
echo $! > $pidfile
