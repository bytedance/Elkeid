#!/bin/bash

if ! type go >/dev/null 2>&1; then
    echo 'go not installed';
    exit 1
fi

#service_discovery
mkdir -p service_discovery/conf
cd ../service_discovery
go build -o ../build/service_discovery/sd main.go
cp conf/* ../build/service_discovery/conf/
cd ../build/
tar cvfz service_discovery-`date "+%Y%m%d%H%M%S"`.tar.gz service_discovery
rm -rf service_discovery

#agent_center
mkdir -p agent_center/conf
cd ../agent_center
go build -o ../build/agent_center/agent_center main.go
cp conf/* ../build/agent_center/conf/
cd ../build/
tar cvfz agent_center-`date "+%Y%m%d%H%M%S"`.tar.gz agent_center
rm -rf agent_center

#manager
mkdir -p manager/conf
cd ../manager
go build -o ../build/manager/manager main.go
go build -o ../build/manager/init init.go
cp conf/* ../build/manager/conf/
cd ../build/
tar cvfz manager-`date "+%Y%m%d%H%M%S"`.tar.gz manager
rm -rf manager
