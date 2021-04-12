#!/bin/bash

# For each domain
# 	Dig removing CNAME entries
#	and take the first from the resolver
#	Format to what the network tool expects
cat "web.raw.dataset" | while read line; do

	ip4=$(dig +short $line A | grep -v '\.$' | head -n 1)
	if [  $? -eq 0  ] && [ ! -z "$ip4" ]; then
  			echo "$ip4 WEB $line"
	fi
	ip6=$(dig +short $line AAAA | grep -v '\.$' | head -n 1)
	if [  $? -eq 0  ] && [ ! -z "$ip6" ]; then
  			echo "$ip6 WEB $line"
	fi

	echo "$ip4,$ip6,$line" >> aux.web.dataset

done
