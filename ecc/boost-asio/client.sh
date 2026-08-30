#!/bin/bash

for a in "hello world" "the quick" "brown fox" "jumped over" "the pangram" "bye world"
do
     netcat 127.0.0.1 25000 <<< "$a" || echo "not sent: '$a'"&
done
wait