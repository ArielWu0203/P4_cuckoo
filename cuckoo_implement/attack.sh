#!/bin/bash
start=$(date +%s)

duration=0

hping3 10.0.0.1 -S -i u200000 -p 80

while [ $duration -lt 60 ]
do
    end=$(date +%s)
    duration=$(( end - start ))
done

exit 0