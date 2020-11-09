#!/bin/bash

# Installer script for AMI images
#       pull correct dependencies
#       install, configure libraries
#       The outputted applications is a ready to go version of the application

NF_URL=https://www.netfilter.org/projects/libnetfilter_queue/files
NF_TGT=libnetfilter_queue-1.0.5
NF_EXT=.tar.bz2

GREPO=https://github.com/mylesalamb/individualProject.git
GREPO_PATH=individualProject/tooling/prod

sudo apt-get update -y
sudo apt-get install -y gcc make cmake wget libmnl-dev libnfnetlink-dev libpcap-dev 

wget "${NF_URL}/${NF_TGT}${NF_EXT}"
tar -xvf "${NF_TGT}${NF_EXT}"

cd $NF_TGT
./configure
make
sudo make install
cd ..

git clone $GREPO
cd $GREPO_PATH
make
