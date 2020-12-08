#!/bin/bash

# For each domain
# 	Dig removing CNAME entries
#	and take the first from the resolver
#	Format to what the network tool expects
cat "web.raw.dataset" | while read line; do

	elt=$(dig +short $line A | grep -v '\.$' | head -n 1)
	if [  $? -eq 0  ] && [ ! -z "$elt" ]; then
	
		
  			echo "$elt WEB $line"
		
	fi

	elt=$(dig +short $line AAAA | grep -v '\.$' | head -n 1)
	if [  $? -eq 0  ] && [ ! -z "$elt" ]; then
  			echo "$elt WEB $line"
	fi

done
