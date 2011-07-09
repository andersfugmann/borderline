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
    
    echo -ne "${TEST_FILE/.bl/}...\t" 
    
    ${BORDERLINE} ${TEST_FILE} > ${TEST_RESULT} 2>&1
    
    if [ $? != 0 ]; then
        echo "FAIL"
        cat ${TEST_RESULT}
        let FAILED++
        return
    fi

    OKS=$(grep -e "^ip6tables.*OK" ${TEST_RESULT} | wc -l)
    ERRORS=$(grep -e "^ip6tables.*ERROR" ${TEST_RESULT} | wc -l)

#    if (( OKS == EXPECTED && ERRORS == 0 )); then
    if (( ERRORS == 0 )); then
        echo -n "success"
        let SUCCESS++
    else
        echo -n "fail"
        let FAILED++
    fi
    echo "(${OKS}, ${ERRORS})"
}    
TESTS=$(ls *.bl | sort)
for test_file in ${TESTS}; do
    execute ${test_file}
done

echo
echo "tests: $(( SUCCESS + FAILED )) success: ${SUCCESS} fail: ${FAILED}"
if (( FAILED == 0 )); then 
    exit 1
else
    exit 0
fi

