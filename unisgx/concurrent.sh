#!/bin/bash
user=$1
password=$2
tries=$3
instances=$4

start=$(($(date +%s%N)/1000000))

for i in $(seq 1 $instances)
do
	# echo "started instance no: $i"
	./auth_test $user $password $tries &
done

wait

end=$(($(date +%s%N)/1000000))

echo "$(($end - $start)) ms"
