#Test utility functionality
#!/bin/bash

CYASSL="./cyassl"
ENC="encrypt"
DEC="decrypt"
HASH="hash"
BENCH="benchmark"
AES="-aes-cbc-"
AES2="-aes-ctr-"
DES="-3des-cbc-"
CAM="camellia-cbc-"
M="-md5"
SHA="-sha"
SHA2="-sha256"
SHA3="-sha384"
SHA5="-sha512"
BLAKE="-blake2b"
zero=0

TIMER="$(date +%s)"

function crypto() {
    COUNTER=8
    SIZEF=1
    SIZET=1

    $CYASSL $ENC $1 -i tests -k tests
    RC=$?
    if [[ $RC -eq $zero ]] ; then 
        until [ $COUNTER -lt 1 ]; do
            echo Creating File of Size $SIZEF...
            IN=$(mktemp /tmp/input.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
            OUT=$(mktemp /tmp/output.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
            KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
            RANDF=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZEF | head -n 1)
            RANDT=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZET | head -n 1)
    
            echo $RANDF  >> $IN
            
            echo $CYASSL $ENC $1 size: $SIZEF bytes
            T="$(date +%s%3N)"
            $CYASSL $ENC $1 -i $IN -o $OUT -k $KEY
            $CYASSL $DEC $1 -i $OUT -o $IN -k $KEY
            T="$(($(date +%s%3N)-T))"
            echo TIME: $T milliseconds
            echo $CYASSL $ENC $1 -i $RANDT
            T="$(($(date +%s%3N)-T))"
            $CYASSL $ENC $1 -i $RANDT -o $OUT -k $KEY
            $CYASSL $DEC $1 -i $OUT -o $IN -k $KEY
            T="$(($(date +%s%3N)-T))"
            echo TIME: $T milliseconds
           
            rm -f $OUT
            rm -f $in
       
            let COUNTER-=1
            let SIZEF*=10
            let SIZET+=10
        done
    else
        echo $1 not currently enabled
    fi
    rm -f encrypted
}

function hashing() {
    COUNTER=9
    SIZEF=1
    SIZET=1
    if $CYASSL hash $1 -i tests; then
        until [ $COUNTER -lt 1 ]; do
            echo Creating File of Size $SIZEF...
            IN=$(mktemp /tmp/input.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
            OUT=$(mktemp /tmp/output.XXXXXXXXXX) || { echo "Failed to create temp file"; exit 1; }
            RANDF=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZEF | head -n 1)
            RANDT=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SIZET | head -n 1)
            echo $RANDF >> $IN
    
            echo $CYASSL hash $1 size: $SIZEF bytes
            T="$(date +%s%3N)"
            $CYASSL hash $1 -i $IN -o $OUT
            T="$(($(date +%s%3N)-T))"
            echo TIME: $T milliseconds
            echo $CYASSL hash $1 -i $RANDT
            T="$(date +%s%3N)"
            $CYASSL hash $1 -i $RANDT -o $OUT
            T="$(($(date +%s%3N)-T))"
            echo TIME: $T milliseconds
    
            rm -f $IN
            rm -f $OUT
    
            let COUNTER-=1
            let SIZEF*=10
            let SIZET+=10
        done
    else
        echo $1 not currently enabled
    fi  
}

crypto $AES\128
crypto $AES\192
crypto $AES\256
crypto $AES2\128
crypto $AES2\192
crypto $AES2\256
crypto $DES\56
crypto $DES\112
crypto $DES\168
crypto $CAM\128
crypto $CAM\192
crypto $CAM\256
hashing $M
hashing $SHA
hashing $SHA2
hashing $SHA3
hashing $SHA5
hashing $BLAKE
$CYASSL benchmark -t 1 -all
TIMER="$(($(date +%s)-TIMER))"
echo TOTAL TEST TIME: $TIMER seconds
