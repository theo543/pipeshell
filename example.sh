#!/bin/sh

printf 'head 0</dev/urandom 22</dev/null -c 1000000 | base64 | fold | grep aaa | tee unsorted.txt | sort > sorted.txt\nprintf \\n 1>> unsorted.txt\ncat unsorted.txt sorted.txt' | ./pipeshell
