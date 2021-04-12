# Individual Project Tooling

This readme describes the contents of the software that was developed for the individual project to realise "Where is ECN stripped on the network". The tooling is broken into three distinct parts. Each contained within a specific folder

* "tool", a set of C files / bash scripts allowing for measurements to be taken from the network.

* "deploy", Terraform / deployment configuration, a set of installer scripts and terraform configuration targetting an AWS deployment.

* "analysis", a collection of python files for parsing outputted data from the network analysis tool and extracting key features of the data.

* "misc", various shell scripts and other utilities that were written across the project to assist with the research goals



## Network Analysis Tool

Please note that as submitted the tool will not work as external (open source) dependencies are required. I highly recommend installing the tool in a virtual machine (ubuntu 20.4)  utilising the steps below


### Installing through the provided installer

ideally, one may install the tool automatially through using the provided installer script
this script has been tested under a new install of Ubuntu 20.4 inside a virtual machine, and is the recomended way
to interact with the tool.

```
wget https://raw.githubusercontent.com/mylesalamb/IndividualProject/master/src/deployment/installer.ubuntu.sh
chmod +x installer.ubuntu.sh 
sudo ./installer.ubuntu.sh
```

there also exists additional installers within the same github repository that are similarily named as follows

```
installer.rpi.sh # targetting raspberry pi 2/3/4
installer.ami.sh # targetting amazon machine images, utilising ubuntu 20.4 (utilised via deploy infrastructure)
```

under the provided installers, only the script is required (the script clones the git repository)
the github repository will be archived after the submission date ensuring no further changes take place to the repository during the marking period.

once the script has finished running the tool will be located in `src/tool/ecnDetector`

### Manual Install

There does exist existing installer scripts which act as a helpful guide in installing the tool properly I thoroughly recommend using these as opposed to installing the tool manually, however I also provide these instructions as a means to explain the contents of the various installers that were produced.

As submitted the code provided will not compile, as it only contains the sources produced by myself. To obtain a working set of the project. it can be cloned from here github.com/mylesalamb/individualProject.git with the following command, cloning submodule dependencies as required to build the tool.

```
git clone --recurse-submodules https://github.com/mylesalamb/individualProject.git
```

We additionally need to install some more dependencies through an appropriate packet manager, for debian/ubuntu based distributions the command required is.

```
sudo apt-get update -y
sudo apt-get install -y clang gcc git-lfs zlib1g-dev golang make cmake wget libmnl-dev libnfnetlink-dev libpcap-dev libev-dev libevent-dev
```

To additionally pull the datasets used in the dissertation one needs to use git lfs as follows

```
cd individualProject
git lfs install
git lfs pull
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

You may also need to update the runtime loader, or avoiding this through altering the install prefix when installing libnetfilter_queue to a path that the runtime loader is aware of. The command to update the runtime loader is as follows...

```
echo "export LD_LIBRARY_PATH=/usr/local/lib:\$LD_LIBRARY_PATH" >> ~/.bashrc
. ~/.bashrc
sudo ldconfig
```

Now, changing directories into the folder `individualProject/src/tool`
you additionally need to compile from source some dependencies that are not distributed via package managers, namely lsquic and boringssl. One of lsquics dependencies. with the folloing commands

(These commands will take a while)
```
cd boringssl/
cmake . && make
BORINGSSL=$PWD
BORINGSSL_INCLUDE=$PWD/include
cd ..

cd lsquic/
cmake -DBORINGSSL_DIR=$BORINGSSL -DBORINGSSL_INCLUDE=$BORINGSSL_INCLUDE . && make
sudo make install
cd ..
```

Lastly, one may compile the tool with the provided makefile with make. First changing directory to the 'tool' directory within the repository.

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

We additionally create a "psuedo" user to better caputre traffic from the network with the following command, through utilising the UID-Owner iptables module

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
These commands are also contained within the file `setup.sh` contained within the `tool` directory


### Running


once the tool has been configured, the tool can be directed to operate on a particular dataset with

```
./ecnDetector -f $DATASET -d $OUTPUT_DIR
```

Where lines of the dataset file take the format
```
IP_ADDR WEB|DNS|NTP SNI 

# For example
192.168.0.1 WEB a.website.com
8.8.8.8 DNS
192.168.0.1 NTP

```

### Known issues

* Attempting to connect to IPv6 hosts from an IPv4 only vantage point seems to trigger some form of undefined behaviour and causes the tool to behave in strange ways. To date im not too sure why this happens, however removing any IPv6 hosts from the dataset suitably avoids this.

* The code will compile under GCC, however raw sockets stop working, this can be likely attributed to additional undefined behaviour being triggered somewhere.

* Depending on how the tool was installed sometimes file permission issues can be encountered, a crude but quick fix for this is: ```chmod -r o+rwx $INSTALL_FOLDER``` where $INSTALL_FOLDER contains all of the files relating to the project


## Deployment infrastructure

The deployment infrastructure utilities require Packer and Terraform to be installed
install instructions can be found here
https://learn.hashicorp.com/tutorials/packer/getting-started-install
https://learn.hashicorp.com/tutorials/terraform/install-cli

### Packer

packer is used to build virtual machine images used by the deployment of this project. This requires an active AWS account with suitable credentials defined in environment variables. Namely,

$AWS_ACCESS_KEY = your aws access key
$AWS_SECRET_KEY = your aws secret key

images can be built and distributed to cloud storage locations with the command

```
packer build -machine-readable deploy-img.json > prebaked
```

note that we pipe the output of the command such that machine image IDs can be passed to terraform via an intermediate tool

### Terraform

After following the required setup under the link provided.
one should first generate appropriate virtual machine images using the instructions provided in the packer section.

One should then generate a file containing the outputted virtual machine image IDs with the following command

```
python3 packer-to-terraform.py --dry prebaked
```

one can then deploy the produced images in each area through the following commands

```
terraform init
terraform plan
terraform apply
```

you can also destroy the produced infrastructure with

```
terraform destroy
```

## Data analysis tooling

having gathered output data containing network measurements, we can analyse the data produced with the following tooling

given a directory `foo` containing trace data with the following structure

```
    instance 
        |
        |
        ----- trace0
                | 
                |
                ---- HOST-PROTO-FLAGS.pcap
    instance2
        |
        |
        ----- trace0
                |
                |
                ---- HOST-PROTO-FLAGS.pcap
```

we can run the data analysis tooling with the following command

```
python main.py -i foo -w . -o .
```

This will produce a variety of json files containing a simplified view of the provided data allowing for faster subsequent analysis (as the initial parse of data takes a very long time)

subsequent runs of the data analysis tool can be performed with

```
python main.py --from-json . -w . -o . --run-analysis
```

The output is largely unstructured / not very clean, but was the means used to produce most of the visualizations present withint the dissertation

