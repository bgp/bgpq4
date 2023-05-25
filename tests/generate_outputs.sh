#!/bin/bash

set -e

if [ $# -ne 2 ]
then
    echo "Usage: pass the following arguments in order:"
    echo ""
    echo "path to bgpq4 binary"
    echo "output directory path"
    echo ""
    echo "${0} ./bgpq4 /tmp"
    exit 1
fi

BGPQ4_PATH="${1}"
TEST_ASN="112"
TEST_AS_SET="AS-AS112"
OUT_DIR="${2}"

if [ ! -f "${BGPQ4_PATH}" ]
then
    echo "File ${BGPQ4_PATH} does't exist"
    exit 1
fi

if [ ! -e "${OUT_DIR}" ]
then
    echo "Output directory ${OUT_DIR} does't exist"
    exit 1
fi

# Test the IPv4 output formatting for each supported NOS:
"${BGPQ4_PATH}" -4 -b "AS${TEST_ASN}" > "${OUT_DIR}/bird--4.txt"
"${BGPQ4_PATH}" -4 -e "AS${TEST_ASN}" > "${OUT_DIR}/eos--4.txt"
"${BGPQ4_PATH}" -4 -F '%n/%l ' "AS${TEST_ASN}" > "${OUT_DIR}/formated--4.txt"
"${BGPQ4_PATH}" -4 -U "AS${TEST_ASN}" > "${OUT_DIR}/huawei--4.txt"
"${BGPQ4_PATH}" -4 -u "AS${TEST_ASN}" > "${OUT_DIR}/huawei-xpl--4.txt"
"${BGPQ4_PATH}" -4 "AS${TEST_ASN}" > "${OUT_DIR}/ios--4.txt"
"${BGPQ4_PATH}" -4 -X "AS${TEST_ASN}" > "${OUT_DIR}/ios-xr--4.txt"
"${BGPQ4_PATH}" -4 -j "AS${TEST_ASN}" > "${OUT_DIR}/json--4.txt"
"${BGPQ4_PATH}" -4 -J "AS${TEST_ASN}" > "${OUT_DIR}/junos--4.txt"
"${BGPQ4_PATH}" -4 -B "AS${TEST_ASN}" > "${OUT_DIR}/openbgpd--4.txt"
"${BGPQ4_PATH}" -4 -K "AS${TEST_ASN}" > "${OUT_DIR}/routeros6--4.txt"
"${BGPQ4_PATH}" -4 -K7 "AS${TEST_ASN}" > "${OUT_DIR}/routeros7--4.txt"
"${BGPQ4_PATH}" -4 -N "AS${TEST_ASN}" > "${OUT_DIR}/sros--4.txt"
"${BGPQ4_PATH}" -4 -n "AS${TEST_ASN}" > "${OUT_DIR}/sros-mdcli--4.txt"
"${BGPQ4_PATH}" -4 -n2 "AS${TEST_ASN}" > "${OUT_DIR}/srlinux--4.txt"

# Test the IPv6 prefix-list output formatting for each supported NOS:
"${BGPQ4_PATH}" -6 -b "AS${TEST_ASN}" > "${OUT_DIR}/bird--6.txt"
"${BGPQ4_PATH}" -6 -e "AS${TEST_ASN}" > "${OUT_DIR}/eos--6.txt"
"${BGPQ4_PATH}" -6 -F '%n/%l ' "AS${TEST_ASN}" > "${OUT_DIR}/formated--6.txt"
"${BGPQ4_PATH}" -6 -U "AS${TEST_ASN}" > "${OUT_DIR}/huawei--6.txt"
"${BGPQ4_PATH}" -6 -u "AS${TEST_ASN}" > "${OUT_DIR}/huawei-xpl--6.txt"
"${BGPQ4_PATH}" -6 "AS${TEST_ASN}" > "${OUT_DIR}/ios--6.txt"
"${BGPQ4_PATH}" -6 -X "AS${TEST_ASN}" > "${OUT_DIR}/ios-xr--6.txt"
"${BGPQ4_PATH}" -6 -j "AS${TEST_ASN}" > "${OUT_DIR}/json--6.txt"
"${BGPQ4_PATH}" -6 -J "AS${TEST_ASN}" > "${OUT_DIR}/junos--6.txt"
"${BGPQ4_PATH}" -6 -B "AS${TEST_ASN}" > "${OUT_DIR}/openbgpd--6.txt"
"${BGPQ4_PATH}" -6 -K "AS${TEST_ASN}" > "${OUT_DIR}/routeros6--6.txt"
"${BGPQ4_PATH}" -6 -K7 "AS${TEST_ASN}" > "${OUT_DIR}/routeros7--6.txt"
"${BGPQ4_PATH}" -6 -N "AS${TEST_ASN}" > "${OUT_DIR}/sros--6.txt"
"${BGPQ4_PATH}" -6 -n "AS${TEST_ASN}" > "${OUT_DIR}/sros-mdcli--6.txt"
"${BGPQ4_PATH}" -6 -n2 "AS${TEST_ASN}" > "${OUT_DIR}/srlinux--6.txt"

# Test the AS path list output formatting for each supported NOS:
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -b > "${OUT_DIR}/bird--asp.txt"
# "${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -e > "${OUT_DIR}/eos--asp.txt" # Not supported
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -U > "${OUT_DIR}/huawei--asp.txt"
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -u > "${OUT_DIR}/huawei-xpl--asp.txt"
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" > "${OUT_DIR}/ios--asp.txt"
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -X > "${OUT_DIR}/ios-xr--asp.txt"
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -j > "${OUT_DIR}/json--asp.txt"
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -J > "${OUT_DIR}/junos--asp.txt"
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -B > "${OUT_DIR}/openbgpd--asp.txt"
# "${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -K > "${OUT_DIR}/routeros6--asp.txt" # Not supported
# "${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -K7 > "${OUT_DIR}/routeros7--asp.txt" # Not supported
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -N > "${OUT_DIR}/sros--asp.txt"
"${BGPQ4_PATH}" "${TEST_AS_SET}" -f "${TEST_ASN}" -n > "${OUT_DIR}/sros-mdcli--asp.txt"

# Test IRR source scopes
# Limit ASN to valid source:
"${BGPQ4_PATH}" "AS${TEST_ASN}" -S RIPE-NONAUTH > "${OUT_DIR}/as112-ripe-nonauth.txt"
# Limit ASN to invalid sources:
"${BGPQ4_PATH}" "AS${TEST_ASN}" -S APNIC,AFRINIC > "${OUT_DIR}/as112-apnic.txt"
# Limit AS-SET using IRR prefix notation to valid source:
"${BGPQ4_PATH}" "RIPE::${TEST_AS_SET}" > "${OUT_DIR}/as-as112-ripe-notation.txt"
# Limit AS-SET using IRR prefix notation to invalid source:
"${BGPQ4_PATH}" "APNIC::${TEST_AS_SET}" > "${OUT_DIR}/as-as112-apnic-notation.txt"
