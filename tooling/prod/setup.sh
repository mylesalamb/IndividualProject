sudo iptables -t mangle -A POSTROUTING -p tcp --sport 6000 -j NFQUEUE
