#!/bin/bash

if (( $# != 1 )); then
        echo "provide arguement"
        exit 1
fi

while read line; do
        echo "checking host: $line"
        if [[ `ntpdate -q $line` ]] &> /dev/null; then
                echo $line
        fi
done < $1