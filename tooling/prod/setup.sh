#!/bin/bash
# iptable rule to send packets to the nfqueue net hook -> to send to userspace
sudo iptables -t mangle -A POSTROUTING -p tcp --sport 6000 -j NFQUEUE
sudo iptables -t mangle -A POSTROUTING -p udp --sport 6000 -j NFQUEUE
