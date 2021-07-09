#!/bin/bash
VER="1"
CMD=""
ARG1=""
ARG2=""
ARG3=""

PID=""
SOCKET_DIR="/tmp"

POSITIONAL=()

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -p|--pid)
    PID="$2"
    shift
    shift
    ;;
    -c|--cmd)
    CMD="$2"
    shift
    shift
    ;;
    --args)
    read -r ARG1 ARG2 ARG3 <<< "$2"
    shift
    shift
    ;;
    *)
    POSITIONAL+=("$1")
    shift
    ;;
esac
done

set -- "${POSITIONAL[@]}"

function INFO() {
    local msg="$1"
    timeAndDate=$(date)
    echo "[$timeAndDate] [INFO]  $msg"
}

if [ "$TMPDIR" ]; then
    SOCKET_DIR="$TMPDIR"
fi

INFO "Socket dir: $SOCKET_DIR"

if [ -z "$PID" ] || [ -z "$CMD" ]; then
    INFO "./script -p {pid} -c {cmd} --args {arguments}"
    exit
fi

if ! kill -s 0 "$PID" &> /dev/null; then
    INFO "Process not exist"
    exit 0
fi

socket_path="$SOCKET_DIR/.java_pid$PID"

if [ ! -e "$socket_path" ]; then
    INFO "Create attach file"

    touch "$SOCKET_DIR/.attach_pid$PID"
    kill -3 "$PID"
fi

payload="$(echo -n "$VER" | xxd -ps)"00"$(echo -n "$CMD" | xxd -ps)"00"$(echo -n "$ARG1" | xxd -ps)"00"$(echo -n "$ARG2" | xxd -ps)"00"$(echo -n "$ARG3" | xxd -ps)"00

INFO "Payload: $payload"
response=$(echo "$payload" | xxd -r -ps | socat - UNIX-CONNECT:"$socket_path")

INFO "Response: $response"
