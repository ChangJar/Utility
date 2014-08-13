#!/bin/bash
GREEN='\e[0;32m'
RED='\e[0;31m'
NC='\e[0m'
ZERO=0
fail=0
i=0
total=0
 
function hashtest() {
    fail=0
    i=0
    total=0
    
    while read -r md; do
        if [[ $i -lt 10 ]]; then
            FILE="/home/cj/Documents/wolfSSL/Utility/tests/byte000$i.dat"
        elif [[ $i -lt 100 ]]; then
            FILE="/home/cj/Documents/wolfSSL/Utility/tests/byte00$i.dat"
        elif [[ $i -lt 1000 ]]; then
            FILE="/home/cj/Documents/wolfSSL/Utility/tests/byte0$i.dat"
        else 
            break
        fi   
#takes last 3 characters off
        md="${md:0:-$3}"
#converts to lowercase
        md=${md,,}
        cipher="$(/home/cj/Documents/wolfSSL/Utility/programs/cyassl hash -$2 -i $FILE -l $i)"
        if test "$cipher" != "$md"; then
            fail=$[fail+1]
        fi
        total=$[total+1]
        i=$[i+1]
    done < $1
    
    if [ $fail = $ZERO ]; then
        echo -e "${GREEN}All $total $2 Tests Passed${NC}"
    else
        echo -e "${RED}$fail/$total $2 Tests Failed${NC}"
    fi
}

echo Testing...
hashtest /home/cj/Documents/wolfSSL/Utility/tests/byte-hashes.sha1 sha 3
hashtest /home/cj/Documents/wolfSSL/Utility/tests/byte-hashes.md5 md5 2
