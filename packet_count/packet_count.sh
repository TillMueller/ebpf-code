#!/bin/bash
pcksFile="/sys/class/net/$1/statistics/rx_packets"
for (( i = 0; i <= $2; i++))
do
	nbPcks=`cat $pcksFile`
	sleep $3
	echo $(expr `cat $pcksFile` - $nbPcks)
done
