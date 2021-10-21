#!/bin/bash

if ! type docker >/dev/null 2>&1; then
    echo 'docker not installed';
    exit 1
fi

echo ">>>>>>>>>>start to build elkeid.com/elkeid-ac:1.0.0!"
cd ../agent_center/
docker build -t elkeid.com/elkeid-ac:1.0.0 .

echo ">>>>>>>>>>start to build elkeid.com/elkeid-mg:1.0.0!"
cd ../manager/
docker build -t elkeid.com/elkeid-mg:1.0.0 .

echo ">>>>>>>>>>start to build elkeid.com/elkeid-sd:1.0.0!"
cd ../service_discovery/
docker build -t elkeid.com/elkeid-sd:1.0.0 .
cd ../build/

echo ">>>>>>>>>>start to export the images!"
docker save -o ./ac.1.0.0.tar elkeid.com/elkeid-ac:1.0.0
docker save -o ./mg.1.0.0.tar elkeid.com/elkeid-mg:1.0.0
docker save -o ./sd.1.0.0.tar elkeid.com/elkeid-sd:1.0.0
echo ">>>>>>>>>>done"


