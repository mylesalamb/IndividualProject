#!/bin/bash

# Script to resolve ip addresses from dataset files to latitude and longtitudes
# So that we can see the distribution of hosts

DATASET_ROOT="../datasets"

DATASET_WEB="$DATASET_ROOT/web.filtered.dataset"
DATASET_NTP="$DATASET_ROOT/ntp.filtered.dataset"
DATASET_DNS="$DATASET_ROOT/dns.filtered.dataset"

WEB_OUT="web.locs"
NTP_OUT="ntp.locs"
DNS_OUT="dns.locs"

echo "[" > $WEB_OUT

while read line; do

    ipaddr=`echo "$line" | awk '{print $1}'`
    comm="http://api.ipstack.com/${ipaddr}?access_key=$IP_STACK_KEY"
    echo "$comm"
    reply=`curl $comm`
    echo "$reply," >> $WEB_OUT

done < $DATASET_WEB

echo "]" >> $WEB_OUT



# NTP hosts

echo "[" > $NTP_OUT

while read line; do

    ipaddr=`echo "$line" | awk '{print $1}'`
    comm="http://api.ipstack.com/${ipaddr}?access_key=$IP_STACK_KEY"
    echo "$comm"
    reply=`curl $comm`
    echo "$reply," >> $NTP_OUT

done < $DATASET_NTP

echo "]" >> $NTP_OUT

# DNS hosts

echo "[" > $DNS_OUT

while read line; do

    ipaddr=`echo "$line" | awk '{print $1}'`
    comm="http://api.ipstack.com/${ipaddr}?access_key=$IP_STACK_KEY"
    echo "$comm"
    reply=`curl $comm`
    echo "$reply," >> $DNS_OUT

done < $DATASET_DNS

echo "]" >> $DNS_OUT