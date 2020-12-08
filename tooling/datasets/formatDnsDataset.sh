#!/bin/bash

# Tiny helper to format dns dataset from public-dns.info

DATASET="dns.raw.dataset"

if [ ! -f $DATASET ]; then
    echo "Dns dataset not in current directory"
    exit 1
fi


cat $DATASET | while read line; do

    echo "$line DNS example.io"

done 