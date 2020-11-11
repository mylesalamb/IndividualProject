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

# Update image to most recent version, and install
# non crit dependencies
sudo apt-get update -y
sudo apt-get install -y gcc make cmake wget libmnl-dev libnfnetlink-dev libpcap-dev 

# pull netfilter 1.0.5
wget "${NF_URL}/${NF_TGT}${NF_EXT}"
tar -xvf "${NF_TGT}${NF_EXT}"

# install and update path accordingly
cd $NF_TGT
./configure
make
sudo make install

echo "$LD_LIBRARY_PATH" | grep -q "$NF_INSTALL_PATH" 

if [ $? -ne 0  ]; then

	echo "export LD_LIBRARY_PATH=$NF_PATH:$LD_LIBRARY_PATH" >> ~/.bashrc
	. ~/.bashrc

fi

cd ..

git clone $GREPO
cd $GREPO_PATH
make
