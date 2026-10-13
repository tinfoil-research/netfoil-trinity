iptables -t nat -I PREROUTING -s 192.168.122.0/24 -p udp --dport 123 -j DNAT --to-destination 192.168.122.1:8123
