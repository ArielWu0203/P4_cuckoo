#!/bin/bash
start=$(date +%s)

duration=0

hping3 $1 -S -i u200000 -p 80 -c 200
