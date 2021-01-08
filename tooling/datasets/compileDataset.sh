#!/bin/sh

NTP_DATASET="ntp.dataset"
DNS_DATASET="dns.dataset"
WEB_DATASET="web.dataset"
OUTPUT="flight.dataset"

if [ ! -f $NTP_DATASET ]; then
	echo "dataset missing"
	exit 1

fi
if [ ! -f $DNS_DATASET ]; then
	echo "dataset missing"
	exit 2

fi
if [ ! -f $WEB_DATASET ]; then
	echo "dataset missing"
	exit 3

fi
shuf -n 1000 $NTP_DATASET > $OUTPUT
shuf -n 1000 $DNS_DATASET >> $OUTPUT
# Keep ipv4/ipv6 addrrs together
head -n 1000 $WEB_DATASET >> $OUTPUT

exit 0
