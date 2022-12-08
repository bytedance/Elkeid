#!/usr/bin/env bash

CURRENT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $CURRENT_DIR
/usr/sbin/nginx -c /opt/tiger/elkeid_console/nginx.conf