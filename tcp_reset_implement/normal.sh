#!/bin/bash
start=$(date +%s)

duration=0
while [ $duration -lt 30 ]
do
    end=$(date +%s)
    duration=$(( end - start ))
    curl $1
    sleep 4s
done
