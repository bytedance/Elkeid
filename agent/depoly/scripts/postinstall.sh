#!/bin/bash
WORK_DIR="/etc/elkeid"
PRODUCT_NAME="elkeid-agent"
SERVICE_NAME="${PRODUCT_NAME}.service"

chmod 700 ${WORK_DIR}/log
chmod 701 ${WORK_DIR}/plugin
chmod 700 ${WORK_DIR}/${PRODUCT_NAME}
chmod 600 ${WORK_DIR}/${SERVICE_NAME}

# when updating,envs will not be set.
if [ -n "${SPECIFIED_IDC}" ];then
echo "SPECIFIED_IDC=${SPECIFIED_IDC}" > ${WORK_DIR}/specified_env
fi
if [ -n "${SPECIFIED_AGENT_ID}" ];then
echo "SPECIFIED_IDC=${SPECIFIED_AGENT_ID}" >> ${WORK_DIR}/specified_env
fi

systemctl link ${WORK_DIR}/${SERVICE_NAME}
systemctl enable ${WORK_DIR}/${SERVICE_NAME}
systemctl start ${SERVICE_NAME}