#!/bin/bash

# iptable rule to send packets to the nfqueue net hook -> to send to userspace
iptables -t mangle -A POSTROUTING -p tcp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
iptables -t mangle -A POSTROUTING -p udp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE

ip6tables -t mangle -A POSTROUTING -p tcp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
ip6tables -t mangle -A POSTROUTING -p udp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE

sudo sysctl -w net.ipv4.tcp_ecn=0
sudo sysctl -w net.ipv4.tcp_syn_retries=3
sudo sysctl -w net.ipv4.tcp_synack_retries=3
