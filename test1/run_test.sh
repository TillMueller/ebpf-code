#!/bin/bash
../xdp_loader/simple_loader -d $1 -f xdp_prog_kern.o -l -m
./write_stats $1
