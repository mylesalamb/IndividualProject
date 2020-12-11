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
apt-get update -y
apt-get install -y clang git-lfs zlib1g-dev golang make cmake wget libmnl-dev libnfnetlink-dev libpcap-dev libev-dev libevent-dev
git lfs install

cd ~


# pull netfilter 1.0.5
wget "${NF_URL}/${NF_TGT}${NF_EXT}"
tar -xvf "${NF_TGT}${NF_EXT}"

# install and update path accordingly
cd $NF_TGT
./configure
make
make install


if echo "$LD_LIBRARY_PATH" | grep -q "$NF_PATH"; then
	echo "*** Already on path"
else
	echo "*** Not on path"
	echo "export LD_LIBRARY_PATH=$NF_PATH:\$LD_LIBRARY_PATH" >> ~/.bashrc
	. ~/.bashrc
fi

if [ ! -z $CI_BUILD ]; then
	cd ~
	git clone --recurse-submodules $GREPO
	cd individualProject/tooling/prod

else
	git submodule update --init --recursive
	cd tooling/prod
fi

cd boringssl/
cmake . && make
BORINGSSL=$PWD
BORINGSSL_INCLUDE=$PWD/include
cd ..

cd lsquic/
cmake -DBORINGSSL_DIR=$BORINGSSL -DBORINGSSL_INCLUDE=$BORINGSSL/include . && make
sudo make install
cd ..

make


if [ ! -z $CI_BUILD ]; then
	sudo setcap cap_net_raw,cap_net_admin=eip ecnDetector
	sudo ldconfig

	# setup the experiement to run in fixed intervals
	sudo service cron stop
	sudo bash -c "echo \"10 2 * * * ubuntu /bin/bash $PWD/test.sh\" >> /etc/crontab"

	# Stop the kernel negotiating ecn on our behalf
	# Alter retry behaviour, a fair number of NTP hosts will be done
	# Dont crash out for ages if this happens, three should be fine in most circumstances
	sudo sysctl -w net.ipv4.tcp_ecn=1
	sudo sysctl -w net.ipv4.tcp_syn_retries=3
	sudo sysctl -w net.ipv4.tcp_synack_retries=3
fi 