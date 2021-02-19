#!/bin/bash

NF_URL=https://www.netfilter.org/projects/libnetfilter_queue/files
NF_TGT=libnetfilter_queue-1.0.5
NF_EXT=.tar.bz2
NF_PATH=/usr/local/lib

GREPO=https://github.com/mylesalamb/individualProject.git
GREPO_PATH=individualProject/tooling/prod


echo "Installer script for Raspberry Pi (2/3/4)"

if [ $UID -ne 0 ]; then
	echo "this should be run as root"
	exit 1
fi

if [ ! `pwd` = "/home/pi" ]; then
	echo "this script should be called from the home directory of the 'pi' user"
	exit 0
fi

# allow all commands to be run as with sudo without intervention
echo "pi ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
useradd ecnDetector_psuedo

apt-get update -y
apt-get install -y clang gcc git-lfs zlib1g-dev golang make cmake wget libmnl-dev libnfnetlink-dev libpcap-dev libev-dev libevent-dev
git lfs install

# pull netfilter 1.0.5
wget "${NF_URL}/${NF_TGT}${NF_EXT}"
tar -xvf "${NF_TGT}${NF_EXT}"

cd $NF_TGT
./configure
make
make install

if echo "$LD_LIBRARY_PATH" | grep -q "$NF_PATH"; then
	echo "*** Already on path"
else
	echo "*** Not on path"
	echo "export LD_LIBRARY_PATH=$NF_PATH:\$LD_LIBRARY_PATH" >> /home/pi/.bashrc
	. /home/pi/.bashrc
	
fi
ldconfig
cd ..

git clone $GREPO
cd individualProject/tooling/prod
git submodule update --init --recursive


# Remove the -Werror warning, some alignment issues with tests on ARM
cd boringssl/
sed -i "s/-Werror//g" CMakeLists.txt
cmake . && make
BORINGSSL=`pwd`
cd ..

cd lsquic/
cmake -DBORINGSSL_DIR=$BORINGSSL -DBORINGSSL_INCLUDE=$BORINGSSL/include . && make
sudo make install
cd ..

make
chmod o+rwx .
# prevent random permissions issues
# with files generated by root
chown -R pi /home/pi

# this must come after the chown step as it clears capabilities
setcap cap_setpcap,cap_net_admin,cap_net_raw,cap_setgid,cap_setuid=+eip ecnDetector
[ $? -ne 0 ] && echo "setcap failed! returning: $?"

cd ..

# Add cron job, but attempting to preserve other jobs that may exist already
CRON=`crontab -l -u pi`
CRON_COM="0 0 * * * $(pwd)/init.sh"
if [ $? -ne 0 ]; then
	echo "$CRON_COM" | crontab -u pi -
else 
	( echo "$CRON"; echo "$CRON_COM"; ) | crontab -u pi -
fi

exit 0
