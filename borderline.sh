#!/bin/bash

### BEGIN INIT INFO
# Provides:          borderline
# Required-Start:    $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     S
# Default-Stop:      0 6
# Short-Description: A firewall compiler
# Description:       Generates a packet filtering firewall for iptables.
### END INIT INFO
#
# chkconfig: 345 08 92
# description: Borderline - A firewall compiler

MAIN=/etc/borderline/borderline.bl
if [ -f /etc/default/borderline ]; then
    . /etc/default/borderline
fi

if [ \! -f "${MAIN}" ]; then
    echo "Invalid or not input file given: ${MAIN}"
    exit 1
fi

IP6TABLES="/sbin/ip6tables"
IP6TABLES_SAVE="/sbin/ip6tables-save"
IP6TABLES_RESTORE="/sbin/ip6tables-restore"
EGREP="/bin/grep -E"
BORDERLINE="/usr/local/sbin/borderline"
ALL_DONE="false"
ALL_OK="true"

function on_exit() {
    if [ "${ALL_DONE}" != "true" ]; then
        ${IP6TABLES_RESTORE} < ${OLD_RULES}
    fi
    rm -f ${OLD_RULES} ${NEW_RULES} ${TEMP_FILE}
}

function on_init() {
    TEMP_FILE=$(mktemp)
    NEW_RULES=$(mktemp)
    OLD_RULES=$(mktemp)
    chmod 600 ${OLD_RULES} ${NEW_RULES} ${TEMP_FILE}
    trap 'on_exit' TERM QUIT KILL EXIT
}

function ip6tables () {
    if [ "${ALL_OK}" != "true" ]; then
        return
    fi
    ${IP6TABLES} "$@"
    res=$?
    if [ $res != 0 ]; then
        echo "iptables returned exit code ${res}"
        echo "    ${IP6TABLES} "$@""
        ALL_OK="false"
    fi
}

function main() {
    on_init
    echo "Applying firewall..."

    ${BORDERLINE} ${MAIN} > ${TEMP_FILE}
    if [ $? != 0 ]; then
        ALL_DONE="false"
        exit -1
    fi
    ${EGREP} '^ip6tables' ${TEMP_FILE} > ${NEW_RULES}

    echo "Backup old rules"
    ${IP6TABLES_SAVE} > ${OLD_RULES}

    ${IP6TABLES} -P INPUT DROP
    ${IP6TABLES} -P OUTPUT DROP
    ${IP6TABLES} -P FORWARD DROP
    echo "Apply new rules."
    ${IP6TABLES} -F
    ${IP6TABLES} -X
    ${IP6TABLES} -Z

    . ${NEW_RULES}

    if [ "${ALL_OK}" = "true" ]; then
        echo "Firewall applied with no errors."
        ALL_DONE="true"
    fi
}

case $1 in
    "start")
        echo "Starting borderline"
        main
        ;;
    "stop")
        echo "Stopping borderline"
        ALL_OK="true"
        ${IP6TABLES} -F
        ${IP6TABLES} -X
        ${IP6TABLES} -Z
        ${IP6TABLES} -P INPUT ACCEPT
        ${IP6TABLES} -P OUTPUT ACCEPT
        ${IP6TABLES} -P FORWARD ACCEPT
        ;;
    "restart")
        $0 stop
        $0 start
        ;;
    *)
        echo "Use $0 <start|stop|restart>"
esac
