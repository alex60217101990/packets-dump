#!/bin/bash
 
INTERVAL="1"  # update interval in seconds
 
if [ -z "$1" ]; then
        echo
        echo usage: $0 [network-interface]
        echo
        echo e.g. $0 eth0
        echo
        echo shows packets-per-second
        exit
fi
 
IF="lo" # $1
echo "$(cat /sys/class/net/${IF}/statistics/rx_packets)"
while true
do
        R1="$(cat /sys/class/net/${IF}/statistics/rx_packets)"
        T1="$(cat /sys/class/net/${IF}/statistics/tx_packets)"
        sleep $INTERVAL
        R2="$(cat /sys/class/net/$IF/statistics/rx_packets)"
        T2="$(cat /sys/class/net/$IF/statistics/tx_packets)"
        TXPPS="$(expr $T2 - $T1)"
        RXPPS="$(expr $R2 - $R1)"
        echo "TX $IF: $TXPPS pkts/s RX $IF: $RXPPS pkts/s"
done