#!/bin/bash

cat "ntp.raw.dataset" | while read line; do
	echo "$line NTP"
done
