#!/bin/bash

mkdir db_org &> /dev/null
mkdir db_out &> /dev/null
cd db_org

apt-get update

apt-get install -y clamav clamav-freshclam libclamav9
echo "apt-get install $?"

freshclam  --datadir=. -l update.log -u $(whoami)
echo "freshclam download finished $?"

sleep 3

chmod 644 ./main.cvd

sigtool --unpack=./main.cvd
echo "sigtool --unpack $?"

sigtool --unpack=./daily.cvd
echo "sigtool --unpack $?"


rm -f $(ls | grep -vE "\.cvd|\.mdb|\.ldb|\.ndb")
echo "sigtool --unpack $?"


cd -
python3 gen_custom_db.py
