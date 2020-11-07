#!/bin/bash

# Installer script for OCI images
#       pull correct dependencies
#       install, configure libraries



wget https://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.5.tar.bz2
tar -xvf libnetfilter_queue-1.0.5.tar.bz2

cd libnetfilter_queue-1.0.5
./configure
make
make install
echo "$PWD" >> /etc/ld.so.conf
cd ..


make
