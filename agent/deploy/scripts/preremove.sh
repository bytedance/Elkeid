#!/bin/bash
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

disable_service() {
	info "disable agent's service"
    expect "${root_dir}/${agent_ctl} disable"
    rm -rf ${sysvinit_dir}/${sysvinit_script}
    succ "service disabled successfully"
}

stop_agent() {
    ${root_dir}/${agent_ctl} stop
}
delete_cgroups() {
    umount ${root_dir}/cgroup/* > /dev/null 2>&1
    rm -rf ${root_dir}/cgroup
}
clean_dirs() {
    rm -rf ${root_dir}/log
    rm -f ${root_dir}/machine-id
    rm -f ${root_dir}/specified_env
    rm -f ${root_dir}/plugin.sock
    rm -f ${root_dir}/stderr ${root_dir}/stdout
    rm -rf ${root_dir}/plugin
    rm -f /bin/${agent_ctl} /usr/bin/${agent_ctl} /usr/local/bin/${agent_ctl}
}
uninstall() {
	disable_service
    stop_agent
    delete_cgroups
    clean_dirs
}
if [ "$1" == 'remove' ] || [ $1 -eq 0 ]; then
    uninstall
fi