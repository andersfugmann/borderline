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
    #rm -f ${OLD_RULES} ${NEW_RULES} ${TEMP_FILE}
    rm -f ${OLD_RULES} ${TEMP_FILE}
}

function on_init() {
    TEMP_FILE=$(mktemp)
    #NEW_RULES=$(mktemp)
    NEW_RULES=/tmp/borderline.rules
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

function iptables () {
    echo "This is not an ipv4 firewall"
    ALL_OK="false"
}

function flush () {
    ip6tables -F
    ip6tables -X
    ip6tables -Z
}

function set_policy () {
    POLICY=$1

    ip6tables -P INPUT ${POLICY}
    ip6tables -P OUTPUT ${POLICY}
    ip6tables -P FORWARD ${POLICY}
}

function apply() {
    on_init
    echo "Generating firewall rules."

    cat <<EOF > ${NEW_RULES}
set_policy DROP
flush
ip6tables -A INPUT -j DROP
ip6tables -A OUTPUT -j DROP
ip6tables -A FORWARD -j DROP
EOF

    ${BORDERLINE} ${MAIN} > ${TEMP_FILE}
    if [ $? != 0 ]; then
        ALL_DONE="false"
        exit -1
    fi
    ${EGREP} '^ip6tables' ${TEMP_FILE} >> ${NEW_RULES}

    cat <<EOF >> ${NEW_RULES}
ip6tables -D INPUT 1
ip6tables -D OUTPUT 1
ip6tables -D FORWARD 1
EOF

    echo "Backup old rules"
    ${IP6TABLES_SAVE} > ${OLD_RULES}

    echo "Apply new rules."
    source ${NEW_RULES}

    if [ "${ALL_OK}" = "true" ]; then
        echo "Firewall applied with no errors."
        ALL_DONE="true"
    fi
}

case $1 in
    "start")
        echo "Starting borderline"
        apply
        ;;
    "stop")
        echo "Stopping borderline"
        flush
        set_policy ACCEPT
        ;;
    "restart")
        $0 start
        ;;
    "panic")
        echo "Closing network access"
        flush
        set_policy DROP
        ;;
    *)
        echo "Use $0 <start|stop|restart|panic>"
esac
