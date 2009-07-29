#!/bin/sh

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

. /etc/default/borderline

if [ \! -f "${MAIN}" ]; then
    echo "Invalid or not input file given: ${MAIN}"
    exit 1
fi

IP6TABLES="/sbin/ip6tables"
IP6TABLES_SAVE="/sbin/ip6tables-save"
IP6TABLES_RESTORE="/sbin/ip6tables-restore"

BG="/usr/local/sbin/borderline"
ALL_DONE="false"

function on_exit() {
    rm -f ${NEW_RULES}

    if [ "${ALL_DONE}" != "true" ]; then
        ${IP6TABLES_RESTORE} < ${OLD_RULES}
    fi
    rm -f ${OLD_RULES}
}

function on_init() {
    NEW_RULES=$(mktemp)
    chmod 600 ${NEW_RULES}
    OLD_RULES=$(mktemp)
    chmod 600 ${OLD_RULES}
    trap 'on_exit' TERM KILL
}

function ip6tables () {
    if [ "${ALL_OK}" != "true" ]; then
        return
    fi
    args="$*"
    ${IP6TABLES} ${args}
    res=$?
    if [ $res != 0 ]; then
        echo "iptables returned exit code ${res}"
        echo "    ${IP6TABLES} ${ARGS}"
        ALL_OK="false"
    fi
}

function main() {
    on_init
    echo "Generating Firewall form file: ${MAIN}"

    # Should test for errors here
    ${BG} ${MAIN} | grep "ip6tables" > ${NEW_RULES}

    ALL_OK="true"
    echo "Backup old rules"
    ${IP6TABLES_SAVE} > ${OLD_RULES}

    echo "Apply new rules."
    ip6tables -F
    ip6tables -X
    ip6tables -Z

    . ${NEW_RULES}

    if [ "${ALL_OK}" = "true" ]; then
        echo "Firewall applied with no errors."
        ALL_DONE="true"
    fi

    on_exit
}

main
















