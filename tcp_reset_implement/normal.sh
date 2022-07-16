#!/bin/bash
start=$(date +%s)

duration=0
while [ $duration -lt 60 ]
do
    end=$(date +%s)
    duration=$(( end - start ))
    curl 10.0.0.1
    sleep 4s
done