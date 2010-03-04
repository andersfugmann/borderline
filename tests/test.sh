#!/bin/bash

BORDERLINE=../src/borderline

FAILED=0
SUCCESS=0

if [ \! -x ${BORDERLINE} ]; then
    echo "Borderline not found"
    exit -1
fi

function execute () {
    TEST_FILE=$1
    TEST_RESULT=${TEST_FILE/.bl/.res}
      
    EXPECTED=$(grep "OK" ${TEST_FILE} | wc -l)
    
    echo -n "${TEST_FILE/.bl/}... " 
    
    ${BORDERLINE} ${TEST_FILE} > ${TEST_RESULT} 2>&1
    
    if [ $? != 0 ]; then
        echo "FAIL"
        let FAILED++
        return
    fi

    OKS=$(grep -e "^ip6tables.*OK" ${TEST_RESULT} | wc -l)
    ERRORS=$(grep -e "^ip6tables.*ERROR" ${TEST_RESULT} | wc -l)

    if (( OKS == EXPECTED && ERRORS == 0 )); then
        echo -n "success"
        let SUCCESS++
    else
        echo -n "fail"
        let FAILED++
    fi
    echo "(${OKS}, ${ERRORS})"
}    

for test_file in *.bl; do
    execute ${test_file}
    
    echo
    echo "tests: $(( SUCCESS + FAILED)) success: ${SUCCESS} fail: ${FAILED}"
done
