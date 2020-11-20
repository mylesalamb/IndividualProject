#!/bin/bash

# Installer script for AMI images
#       pull correct dependencies
#       install, configure libraries
#       The outputted applications is a ready to go version of the application

NF_URL=https://www.netfilter.org/projects/libnetfilter_queue/files
NF_TGT=libnetfilter_queue-1.0.5
NF_EXT=.tar.bz2
NF_PATH=/usr/local/lib

GREPO=https://github.com/mylesalamb/individualProject.git
GREPO_PATH=individualProject/tooling/prod

BSSLREPO=https://boringssl.googlesource.com/boringssl
BSSL_PATH=boringssl

LSREPO=https://github.com/litespeedtech/lsquic.git
LSREPO_PATH=lsquic
LSREPO_SHA=b117a3a0b7bd11fe6ebd503ec6b45d6b910b41a1
# Update image to most recent version, and install
# non crit dependencies
sudo apt-get update -y
sudo apt-get install -y gcc g++ zlib1g-dev golang make cmake wget libmnl-dev libnfnetlink-dev libpcap-dev libevent-dev

cd ~

# pull netfilter 1.0.5
wget "${NF_URL}/${NF_TGT}${NF_EXT}"
tar -xvf "${NF_TGT}${NF_EXT}"

# install and update path accordingly
cd $NF_TGT
./configure
make
sudo make install


if echo "$LD_LIBRARY_PATH" | grep -q "$NF_PATH"; then
	echo "*** Already on path"
else
	echo "*** Not on path"
	echo "export LD_LIBRARY_PATH=$NF_PATH:\$LD_LIBRARY_PATH" >> ~/.bashrc
	. ~/.bashrc
fi

# setup boring ssl (lsquic dependency)
cd ~
git clone $BSSLREPO
cd $BSSL_PATH
git checkout $LSREPO_SHA
cmake . && make
BORINGSSL=$PWD


# Setup lsquic library
cd ~
git clone $LSREPO
cd $LSREPO_PATH
git submodule init
git submodule update 
cmake -DBORINGSSL_DIR=$BORINGSSL -DBORINGSSL_INCLUDE=$BORINGSSL/include . && make
sudo make install

# TODO:	add cronjjob to run the dataset once daily
#		Save ip(6)tables rules so that we dont have to use root at runtime

# Setup the ecn tool
cd ~
git clone $GREPO
cd $GREPO_PATH
make
