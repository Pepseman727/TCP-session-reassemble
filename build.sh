#!/bin/bash
gcc $1 -lpcap -o compilated.out
./compilated.out $2
