#!/bin/bash

set -x

NIC=eth0

# add tc queuing discipline (egress and ingress buffer)
sudo tc qdisc del dev $NIC clsact 2>&1 >/dev/null
sudo tc qdisc add dev $NIC clsact

# load bpf code into the tc egress and ingress hook respectively
sudo tc filter add dev $NIC egress bpf da obj /tmp/redirect.o sec egress
sudo tc filter add dev $NIC ingress bpf da obj /tmp/redirect.o sec ingress

# show info
sudo tc filter show dev $NIC egress
sudo tc filter show dev $NIC ingress



#sudo tc qdisc del dev $NIC ingress
#sudo tc qdisc del dev $NIC root

tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 match ip dport 4224 0xffff action nat ingress 172.28.1.1 172.28.1.2

tc filter add dev eth0 protocol ip  parent 1: prio 1 u32 match ip dst 172.28.1.1 match ip dport 4224 0xffff flowid 1:1

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 4224 -j DNAT \
      --to 172.28.1.2:7777

tc filter add dev eth0 parent ffff: protocol ip prio 1 u32 match ip dport 4224 action nat ingress 172.28.1.1 172.28.1.2
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip src $TOIP action nat egress $TOIP $FROMIP


