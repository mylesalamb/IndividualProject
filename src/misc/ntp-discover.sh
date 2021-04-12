#!/bin/sh
#
# Script to discover the NTP pool servers
# 
# Copyright (C) 2015 University of Glasgow
# All rights reserved 

# This script was provided by Dr Colin Perkins
# as a means to gather NTP pool servers, subtley modified
# to additioanlly probe from other pools to gather a collection IPv6 pool hosts

if [ ! -d data/ntp-pool ]; then
  mkdir data/ntp-pool
fi

query_zone () {
  if [ ! -d data/ntp-pool/$1 ]; then
    mkdir data/ntp-pool/$1
  fi

  time=`date "+%F %T" `
  echo "*** $time | query_zone $1"

  addrs=`dig +short $1`
  if [ $? != 0 ]; then
    echo "Error"
    exit
  fi

  for i in $addrs
  do
    if [ ! -f data/ntp-pool/$1/$i ]; then
      echo "    Found new server: $i"
      echo $time > data/ntp-pool/$1/$i
    fi
  done 
}

# List of all ISO country codes
countries="AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH
           BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL
           CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET
           FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU
           GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE
           KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC
           MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC
           NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT
           PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR
           SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA
           UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"

# List of all continents in the NTP pool
continents="africa asia europe north-america south-america oceania"

# Loop, repeatedly querying the pool DNS for possible servers
while true; do
  query_zone pool.ntp.org

  for subdomain in $continents $countries
  do
    sleep 1
    query_zone $subdomain.pool.ntp.org
  done

  query_zone 2.pool.ntp.org

  find data/ntp-pool/ -type f -exec basename {} \; | sort | uniq > data/ntp-pool.dat
  server_count=`wc -l < data/ntp-pool.dat`

  echo "*** Found $server_count servers"
  sleep 300
  echo ""
done

