#!/bin/bash
#!/usr/bin/env bash
product_name="elkeid-agent"
root_dir="/etc/elkeid"
service_unit="elkeid-agent.service"
sysvinit_script="elkeid-agent.sysvinit"
sysvinit_dir="/etc/init.d/"
agent_ctl="elkeidctl"
error(){
    echo -e "\e[91m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[ERRO]\t$1\e[0m"
}
warn(){
    echo -e "\e[93m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[WARN]\t$1\e[0m"
}
info(){
    echo -e "\e[96m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[INFO]\t$1\e[0m"
}
succ(){
    echo -e "\e[92m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[SUCC]\t$1\e[0m"
}
expect(){
    $1
    rtc=$?
    if [ $rtc -ne 0 ]; then
        if [ -n "$2" ]; then
            $2
        fi
	    error "when exec $1, an unexpected error occurred, code: $rtc"
	    exit $rtc
	fi
}

enable_service() {
	info "enable agent's service"
	if command -v systemctl > /dev/null 2>&1; then
		expect "${root_dir}/${agent_ctl} set --service_type=systemd"
	else
        expect "mkdir -p ${sysvinit_dir}"
        expect "mkdir -p /etc/cron.d"
        expect "cp ${root_dir}/${sysvinit_script} ${sysvinit_dir}/${product_name}"
        expect "${root_dir}/${agent_ctl} set --service_type=sysvinit"
    fi
    expect "${root_dir}/${agent_ctl} enable"
	succ "service enabled successfully"
}
start_agent(){
    ${root_dir}/${agent_ctl} start
}
reload_service(){
    ${root_dir}/${agent_ctl} service-reload
}
cleanup(){
    ${root_dir}/${agent_ctl} cleanup
}
set_env(){
    if [ -n "${SPECIFIED_IDC}" ];then
        ${root_dir}/${agent_ctl} set --idc=${SPECIFIED_IDC}
    fi
    if [ -n "${SPECIFIED_AGENT_ID}" ];then
       ${root_dir}/${agent_ctl} set --id=${SPECIFIED_AGENT_ID}
    fi
     if [ -n "${SPECIFIED_REGION}" ];then
       ${root_dir}/${agent_ctl} set --id=${SPECIFIED_REGION}
    fi
}
install(){
    enable_service
    set_env
    reload_service
    cleanup
    start_agent
    succ "installation finished successfully"
}
upgrade(){
    enable_service
    reload_service
    cleanup
    succ "upgrade finished successfully"
}

if [ "$1" = "configure" -a -z "$2" ] || [ "$1" == "1" ]
then
    install
elif [ "$1" = "configure" -a -n "$2" ] || [ "$1" == "2" ]
then
    upgrade
fi