#!/bin/bash
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

if command -v systemctl >/dev/null;then
    exit 0
elif command -v update-rc.d >/dev/null || command -v chkconfig >/dev/null;then
    if command -v crontab >/dev/null;then
        exit 0
    else
        error "when using update-rc.d or chkconfig, crontab must be installed"
        exit 1
    fi
else
    error "system must has one of [ systemctl update-rc.d chkconfig ]"
    exit 1
fi