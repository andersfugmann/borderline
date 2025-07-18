#!/bin/bash

FAILED=0
SUCCESS=0

if [ ! -x "${BORDERLINE}" ]; then
    echo "Borderline not found"
    exit -1
fi

function execute () {
    TEST_FILE=$1
    TEST_RESULT=${TEST_FILE/.bl/.res}

    EXPECTED=$(grep -o '"OK[^"]*"' ${TEST_FILE} | sort -u | wc -l)
    COUNT=$(grep -o '"OK[^"]*"' ${TEST_FILE} | wc -l)
    if (( EXPECTED < COUNT )); then
        echo "Error in test ${TEST_FILE}: All ok results must be distinct"
        echo "Found duplicate values: $(grep -o '"OK[^"]*"' ${TEST_FILE} | sort | uniq -d)"
        exit 2
    fi

    echo -ne "${TEST_FILE/.bl/}...\t"

    echo "#!/usr/sbin/nft" > ${TEST_RESULT}
    ${BORDERLINE} ${TEST_FILE} >> ${TEST_RESULT} 2>&1

    if [ $? != 0 ]; then
        echo "FAIL"
        cat ${TEST_RESULT}
        let FAILED++
        return
    fi

    OKS=$(grep -o '"OK[^"]*"' ${TEST_RESULT} | sort -u | wc -l)
    ERRORS=$(grep -e '"ERROR[^"]*"' ${TEST_RESULT} | sort -u | wc -l)

#    if (( OKS == EXPECTED && ERRORS == 0 )); then
    if (( ERRORS == 0 && OKS == EXPECTED)); then
        echo -n "success"
        let SUCCESS++
    else
        echo -n "fail. Expected (${EXPECTED}, 0). Got:  "
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
if (( FAILED != 0 )); then
    exit 1
else
    exit 0
fi
