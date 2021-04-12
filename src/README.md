# Individual Project Tooling

This readme describes the contents of the software that was developed for the individual project to realise "Where is ECN stripped on the network". The tooling is broken into three distinct parts. Each contained within a specific folder

* "tool", a set of C files / bash scripts allowing for measurements to be taken from the network.

* "deploy", Terraform / deployment configuration, a set of installer scripts and terraform configuration targetting an AWS deployment.

* "analysis", a collection of python files for parsing outputted data from the network analysis tool and extracting key features of the data.

## Network Analysis Tool


### Installing through provided installer

ideally, one may install the tool automatially through using the provided installer script

```
wget 
```


### Manual Install

There does exist existing installer scripts which act as a helpful guide in installing the tool properly I thoroughly recommend using these as opposed to installing the tool manually
, however I also provide these instructions as a means to explain the contents of the various installers that were produced.

As submitted the code provided will not compile, as it only contains the sources produced by myself. To obtain a working set of the project. it can be cloned from here github.com/mylesalamb/individualProject.git with the following command, cloning submodule dependencies as required to build the tool.

```
git clone --recurse-submodules https://github.com/mylesalamb/individualProject.git
```

We additionally need to install some more dependencies through an appropriate packet manager, for debian/ubuntu based distributions the command required is.

```
sudo apt-get update -y
sudo apt-get install -y clang gcc git-lfs zlib1g-dev golang make cmake wget libmnl-dev libnfnetlink-dev libpcap-dev libev-dev libevent-dev
```

We need to additionally install one dependency from source, as the common version shipped under many distributions contains a known bug (relating to checksum calculations, subsequently causing packets to be dropped on the network). The commands required to do this are.

```
wget "https://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.5.tar.bz2"
tar -xvf "libnetfilter_queue-1.0.5.tar.bz2"

cd libnetfilter_queue-1.0.5
./configure
make
sudo make install
```

You may also need to update the runtime loader, or avoiding this through altering the install prefix when installing libnetfilter_queue to a path that the runtime loader is aware of.

```
echo "export LD_LIBRARY_PATH=/usr/local/lib:\$LD_LIBRARY_PATH" >> ~/.bashrc
. ~/.bashrc
sudo ldconfig
```

Now, changing directories into the folder `individualProject/src/tool`
you additionally need to compile from source some dependencies that are not distributed via package managers, namely lsquic and boringssl. One of lsquics dependencies. with the folloing commands

```
cd boringssl/
cmake . && make
BORINGSSL=$PWD
BORINGSSL_INCLUDE=$PWD/include
cd ..

cd lsquic/
cmake -DBORINGSSL_DIR=$BORINGSSL -DBORINGSSL_INCLUDE=$BORINGSSL/include . && make
sudo make install
cd ..
```

Lastly, one may compile the tool with the provided makefile with make.
additionally as the tool uses raw sockets in some parts, and listens to network interfaces we require some capabilities to be set with the following command.

```
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_setuid,cap_setgid=eip ecnDetector
```


### Cofiguration



For the deployment of the tool the following kernel parameters were set to make things a little faster. and to prevent the operating system from attempting to negotiate ECN.

```
sudo sysctl -w net.ipv4.tcp_ecn=0
sudo sysctl -w net.ipv4.tcp_syn_retries=3
sudo sysctl -w net.ipv4.tcp_synack_retries=3
```

We additionally create a "psuedo" user to better caputre traffic from the network with the following command

```
sudo useradd ecnDetector_psuedo
```


We additionally require traffic to be directed to netfilter_queue so that modifications can take place with the following commands

```
iptables -t mangle -A POSTROUTING -p tcp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
iptables -t mangle -A POSTROUTING -p udp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE

ip6tables -t mangle -A POSTROUTING -p tcp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
ip6tables -t mangle -A POSTROUTING -p udp -m owner --uid-owner ecnDetector_psuedo -j NFQUEUE
```

### Running


once the tool has been configured, the tool can be directed to operate on a particular dataset with

```
./ecnDetector -f $DATASET -d $OUTPUT_DIR
```

Where lines of the dataset file take the format
```
IP_ADDR WEB|DNS|NTP SNI 

192.168.0.1 WEB a.website.com
8.8.8.8 DNS
192.168.0.1 NTP

```

### Known issues

* Attempting to connect to IPv6 hosts from an IPv4 only vantage point seems to trigger some form of undefined behaviour and causes the tool to behave in strange ways. To date im not too sure why this happens, however removing any IPv6 hosts from the dataset suitably avoids this.

* The code will compile under GCC, however raw sockets stop working, this can be likely attributed to additional undefined behaviour being triggered somewhere.

* Depending on how the tool was installed sometimes file permission issues can be encountered, a crude but quick fix for this is: ```chmod -r o+rwx $INSTALL_FOLDER``` where $INSTALL_FOLDER contains all of the files relating to the project


