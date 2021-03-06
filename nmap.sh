#!/bin/bash

ip=$1

echo "####"
echo "Doing full port scan on $1"
echo "####"
nmap -T4 -p- --min-rate=400 -oG $1-ports.txt $1
string=$(cat $1-ports.txt | grep open | cut -d$'\t' -f2 | cut -d":" -f2)
IFS=', ' read -r -a array <<< "$string"
echo "####"
echo "Performing -sV -A scan now"
echo "####"
for e in "${array[@]}"
do
	IFS='/' read -r -a port <<< "$e"
	nmap -sV -A -p "${port[0]}" $1 >> $1-nmap-enum.txt
done

echo "Done: Results in $1-nmap-enum.txt"
