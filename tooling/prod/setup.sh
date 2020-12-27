#!/bin/bash

# iptable rule to send packets to the nfqueue net hook -> to send to userspace
iptables -t mangle -A POSTROUTING -p tcp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
iptables -t mangle -A POSTROUTING -p udp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE

ip6tables -t mangle -A POSTROUTING -p tcp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
ip6tables -t mangle -A POSTROUTING -p udp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
