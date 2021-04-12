#!/bin/bash

if  [ ! -f "$HOME/ipaddrs" ] || [ ! -f "$HOME/masterKey.pem" ]; then
	echo "missing some files";
	exit 1
fi


while read -r line
do
    field1=$(echo "$line" | awk -F',' '{printf "%s", $1}' | tr -d ',')
    field2=$(echo "$line" | awk -F',' '{printf "%s", $2}' | tr -d ',')

    if [[ $field1 = \#* ]]; then
	continue
    fi
    echo "$field1 $field2"
    comm="scp -i $HOME/masterKey.pem ubuntu@$field1:/home/ubuntu/individualProject/tooling/prod/*.all.tar.gz ."
    
    echo "$comm"
    `$comm`	 

done < "$HOME/ipaddrs"

