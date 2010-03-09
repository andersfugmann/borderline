#!/bin/bash

# Copyright 2009 Anders Fugmann.
# Distributed under the GNU General Public License v3
#
# This file is part of Borderline - A Firewall Generator
#
# Borderline is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# Borderline is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Borderline.  If not, see <http://www.gnu.org/licenses/>.

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

EGREP=/bin/egrep
BG="/usr/local/sbin/borderline"
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

    ${BG} ${MAIN} > ${TEMP_FILE} 2>&1
    if [ $? != 0 ]; then
        ALL_DONE="false"
        exit -1
    fi
    ${EGREP} '^ip6tables' ${TEMP_FILE} > ${NEW_RULES}

    echo "Backup old rules"
    ${IP6TABLES_SAVE} > ${OLD_RULES}

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
        ip6tables -F
        ip6tables -X
        ip6tables -Z
        ip6tables -P INPUT ACCEPT
        ip6tables -P OUTPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ;;
    "restart")
        $0 stop
        $0 start
        ;;
    *)
        echo "Use $0 <start|stop|restart>"
esac
