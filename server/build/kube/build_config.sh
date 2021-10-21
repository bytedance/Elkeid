#!/bin/bash
#usage ./build_config.sh -t simple/full
#example ./build_config.sh -t full

runType="full"
while getopts ":t:h" optname
do
    case "$optname" in
      "t")
        runType=$OPTARG
        ;;
      "h")
        echo "usage: ./build_config.sh -t simple/full"
        echo "      simple: Do not update the certificate."
        echo "      full(default):Generate new certificate and replace it."
        echo "example: ./build_config.sh -t full"
        echo "example: ./build_config.sh"
        exit
        ;;
      ":")
        echo "No argument value for option $OPTARG"
        exit
        ;;
      "?")
        echo "Unknown option $OPTARG"
        exit
        ;;
      *)
        echo "Unknown error while processing options"
        exit
        ;;
    esac
done

if [ "$runType" == "full" ]; then
   cd ..
   ./cert_gen.sh elkeid.com hids-svr elkeid@elkeid.com
   echo "generate new certificate ok!"
   cd kube
fi

if [ ! -f ../cert/ca.crt ]; then echo "File ../cert/ca.crt Not Exist!"; exit ; fi
if [ ! -f ../cert/ca.key ]; then echo "File ../cert/ca.key Not Exist!" ; exit ; fi
if [ ! -f ../cert/client.crt ]; then echo "File ../cert/client.crt Not Exist!"; exit ; fi
if [ ! -f ../cert/client.key ]; then echo "File ../cert/client.key Not Exist!"; exit ; fi
if [ ! -f ../cert/server.crt ]; then echo "File ../cert/server.crt Not Exist!"; exit ; fi
if [ ! -f ../cert/server.key ]; then echo "File ../cert/server.key Not Exist!"; exit ; fi

ac_ak=$(tr -dc 'a-z0-9' < /proc/sys/kernel/random/uuid| cut -c1-16)
ac_sk=$(tr -dc 'a-z0-9' < /proc/sys/kernel/random/uuid| cut -c1-32)
manager_ak=$(tr -dc 'a-z0-9' < /proc/sys/kernel/random/uuid | cut -c1-16)
manager_sk=$(tr -dc 'a-z0-9' < /proc/sys/kernel/random/uuid | cut -c1-32)
manager_key=$(tr -dc 'a-z0-9' < /proc/sys/kernel/random/uuid | cut -c1-32)
echo "generate new key ok!"

rm -f kube_elkeid_svc.yaml
cp kube_elkeid_svc.sample kube_elkeid_svc.yaml
sed -i s#\<\<AC_AK\>\>#"${ac_ak}"#g  ./kube_elkeid_svc.yaml
sed -i s#\<\<AC_SK\>\>#"${ac_sk}"#g  ./kube_elkeid_svc.yaml
sed -i s#\<\<MG_AK\>\>#"${manager_ak}"#g  ./kube_elkeid_svc.yaml
sed -i s#\<\<MG_SK\>\>#"${manager_sk}"#g  ./kube_elkeid_svc.yaml
sed -i s#\<\<API_SECRET\>\>#"${manager_key}"#g  ./kube_elkeid_svc.yaml
echo "update kube_elkeid_svc key ok!"

ca_crt=$(sed ':a;N;s/\n/\\n    /g;ta' ../cert/ca.crt)
ca_key=$(sed ':a;N;s/\n/\\n    /g;ta' ../cert/ca.key)
server_crt=$(sed ':a;N;s/\n/\\n    /g;ta' ../cert/server.crt)
server_key=$(sed ':a;N;s/\n/\\n    /g;ta' ../cert/server.key)
sed -i s#\<\<CA_CRT\>\>#"${ca_crt}"#g  ./kube_elkeid_svc.yaml
sed -i s#\<\<CA_KEY\>\>#"${ca_key}"#g  ./kube_elkeid_svc.yaml
sed -i s#\<\<SERVER_CRT\>\>#"${server_crt}"#g  ./kube_elkeid_svc.yaml
sed -i s#\<\<SERVER_KEY\>\>#"${server_key}"#g  ./kube_elkeid_svc.yaml
echo "update kube_elkeid_svc certificate ok!"

echo "success!"
