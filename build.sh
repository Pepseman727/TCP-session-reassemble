#!/bin/bash
gcc $1 -lpcap -o Build/compilated.out
./compilated.out $2
