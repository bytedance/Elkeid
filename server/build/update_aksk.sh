#!/bin/bash

if [ ! -f ../agent_center/conf/svr.yml  ]; then echo "File agent_center/conf/svr.yml Not Exist!" ; exit ; fi
if [ ! -f ../service_discovery/conf/conf.yaml ]; then echo "File service_discovery/conf/conf.yaml Not Exist!"; exit ; fi
if [ ! -f ../manager/conf/svr.yml ]; then echo "File service_discovery/conf/conf.yaml Not Exist"; exit ; fi

ac_ak=` cat /proc/sys/kernel/random/uuid | tr -dc 'a-z0-9' | cut -c1-16 `
ac_sk=` cat /proc/sys/kernel/random/uuid | tr -dc 'a-z0-9' | cut -c1-32 `
manager_ak=` cat /proc/sys/kernel/random/uuid | tr -dc 'a-z0-9' | cut -c1-16 `
manager_sk=` cat /proc/sys/kernel/random/uuid | tr -dc 'a-z0-9' | cut -c1-32 `
manager_key=` cat /proc/sys/kernel/random/uuid | tr -dc 'a-z0-9' | cut -c1-32  `

echo "generate key ok!"
sed -i s/7abyAiYf56JOWGHp/${ac_ak}/g  ../agent_center/conf/svr.yml
sed -i s/L3E56PpoCoKktzUSlZc1zQdq1x2n9ign/${ac_sk}/g  ../agent_center/conf/svr.yml
sed -i s/0376b2a4c481sef5/${manager_ak}/g  ../agent_center/conf/svr.yml
sed -i s/60b29se7164027072799f565eb964d91/${manager_sk}/g  ../agent_center/conf/svr.yml
echo "update agent_center/conf/svr.yml ok!"

sed -i s/7abyAiYf56JOWGHp/${ac_ak}/g  ../service_discovery/conf/conf.yaml
sed -i s/L3E56PpoCoKktzUSlZc1zQdq1x2n9ign/${ac_sk}/g  ../service_discovery/conf/conf.yaml
sed -i s/vEVL5zEvSiXDY1EI/${manager_ak}/g  ../service_discovery/conf/conf.yaml
sed -i s/2FfQR1FzxRqJRraOw4DGFH7UJieccrGi/${manager_sk}/g  ../service_discovery/conf/conf.yaml
echo "update service_discovery/conf/conf.yaml ok!"

sed -i s/VUjQhmNlUHDotni9/${manager_ak}/g  ../manager/conf/svr.yml
sed -i s/sfhSDLz124J80ioGIyuWsTX9lDxwFdpk/${manager_sk}/g  ../manager/conf/svr.yml
sed -i s/ASpQO2kzFcosGHavUP9BJkn5pcFGIjeg/${manager_key}/g  ../manager/conf/svr.yml
sed -i s/vEVL5zEvSiXDY1EI/${manager_ak}/g  ../manager/conf/svr.yml
sed -i s/2FfQR1FzxRqJRraOw4DGFH7UJieccrGi/${manager_sk}/g  ../manager/conf/svr.yml
sed -i s/0376b2a4c481sef5/${manager_ak}/g  ../manager/conf/svr.yml
sed -i s/60b29se7164027072799f565eb964d91/${manager_sk}/g  ../manager/conf/svr.yml

echo "update manager/conf/svr.yml ok!"
echo "success!"
