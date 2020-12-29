#!/bin/bash

cat "up.ntp.dataset" | while read line; do
	echo "$line NTP"
done
