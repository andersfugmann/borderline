#!/bin/bash

FAILED=0
SUCCESS=0
WARN=0

if [ ! -x "${BORDERLINE}" ]; then
    BORDERLINE="dune exec borderline -- "
fi

function check_output () {
    local test_file=$1 result=$2 line assertion expected pattern actual status
    local first second first_line second_line failed=0
    while IFS= read -r line || [[ -n $line ]]; do
        case "$line" in
            '# EXPECT-COUNT: '*)
                assertion=${line#'# EXPECT-COUNT: '}
                expected=${assertion%% => *}
                pattern=${assertion#* => }
                if [[ ! $expected =~ ^[0-9]+$ || $pattern == "$assertion" || -z $pattern ]]; then
                    echo "Invalid EXPECT-COUNT assertion in ${test_file}: ${line}"
                    failed=1
                    continue
                fi
                actual=$(grep -F -c -- "$pattern" "$result")
                status=$?
                if (( status > 1 )); then
                    echo "Could not check output in ${result}"
                    return 1
                fi
                if (( actual != 10#$expected )); then
                    echo "Expected ${expected} output lines containing '${pattern}', got ${actual}"
                    failed=1
                fi
                ;;
            '# EXPECT-ORDER: '*)
                assertion=${line#'# EXPECT-ORDER: '}
                first=${assertion%% => *}
                second=${assertion#* => }
                if [[ $second == "$assertion" || -z $first || -z $second ]]; then
                    echo "Invalid EXPECT-ORDER assertion in ${test_file}: ${line}"
                    failed=1
                    continue
                fi
                first_line=$(grep -n -F -- "$first" "$result" | head -n 1 | cut -d: -f1)
                second_line=$(grep -n -F -- "$second" "$result" | head -n 1 | cut -d: -f1)
                if [[ -z $first_line || -z $second_line ]] || (( first_line >= second_line )); then
                    echo "Expected '${first}' before '${second}' in ${result}"
                    failed=1
                fi
                ;;
            '# EXPECT-'*)
                echo "Unknown output assertion in ${test_file}: ${line}"
                failed=1
                ;;
        esac
    done < "$test_file"
    return "$failed"
}

function execute () {
    TEST_FILE=$1
    TEST_RESULT=${TEST_FILE/.bl/.res}

    EXPECTED=$(grep -v '^# EXPECT-' ${TEST_FILE} | grep -o '"OK[^"]*"' | sort -u | wc -l)
    COUNT=$(grep -v '^# EXPECT-' ${TEST_FILE} | grep -o '"OK[^"]*"' | wc -l)
    if (( EXPECTED < COUNT )); then
        echo "Error in test ${TEST_FILE}: All OK results must be distinct"
        echo "Found duplicate values: $(grep -v '^# EXPECT-' ${TEST_FILE} | grep -o '"OK[^"]*"' | sort | uniq -d)"
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

    CHECKS=0
    check_output "$TEST_FILE" "$TEST_RESULT" || CHECKS=1

    if (( OKS == EXPECTED && ERRORS == 0 && CHECKS == 0 )); then
        echo -n "success"
        let SUCCESS++
    else
        if (( OKS == EXPECTED && CHECKS == 0 )); then
            echo -n "warn. Expected (${EXPECTED}, 0). Got:  "
            let WARN++
        else
            echo -n "error. Expected (${EXPECTED}, 0). Got:  "
            let FAILED++
        fi
    fi
    echo "(${OKS}, ${ERRORS})"

}
TESTS=$(ls *.bl | sort)
for test_file in ${TESTS}; do
    execute ${test_file}
done

echo
echo "tests: $(( SUCCESS + WARN + FAILED ))"
echo "* success: ${SUCCESS}"
echo "* warnings: ${WARN}"
echo "* fail: ${FAILED}"

if (( FAILED != 0 )); then
    exit 1
else
    exit 0
fi
