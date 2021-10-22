#!/bin/bash
WORK_DIR="/etc/elkeid"
PRODUCT_NAME="elkeid-agent"
SERVICE_NAME="${PRODUCT_NAME}.service"

if [ "$1" == 'remove' ] || [ "$1" == '0' ]; then
    systemctl stop ${SERVICE_NAME}
    systemctl disable ${SERVICE_NAME}
    rm -rf ${WORK_DIR}/plugin/* \
    ${WORK_DIR}/log/* \
    ${WORK_DIR}/machine-id \
    /${WORK_DIR}/specified_env
fi