# Timelog

* Where is ECN Stripped On The Network?
* Myles Lamb
* 2325727L
* Dr Colin Perkins

## Guidance

* This file contains the time log for your project. It will be submitted along with your final dissertation.
* **YOU MUST KEEP THIS UP TO DATE AND UNDER VERSION CONTROL.**
* This timelog should be filled out honestly, regularly (daily) and accurately. It is for *your* benefit.
* Follow the structure provided, grouping time by weeks.  Quantise time to the half hour.

## Week 1

### 30 Sep 2020

* *2 hours* Reading hall of fame projects
* *1 hour* Reading project guidance documents
* *1 hour* Preliminary background reading (Is ECN usable with UDP, Revision on ECN)
* *1 hour* Evaluation of packet sniffers / manglers (libpcap, Scapy)

### 1 Oct 2020

* *1.5 hours* git setup + population
* *1 hour* meeting preparation, mindmap 
* *0.5 hours* Initial project meeting
* *2 hours* Reading ECN RFC and is ECN usable with UDP

### 2 Oct 2020

* *4 hours* reading cited papers from "is ECN usable with UDP"

## Week 2

### 7 Oct 2020

* *1.5 hours* Agenda plan for meeting 8-10-2020 and preliminary timing plan for project

### 8 Oct 2020

* *1.5 hours* Meeting + preparation
* *4 hours* Various readings + technology evaluation (PATHSpider, tracebox, Openssl, libressl, quic implementations) investigating ICMP probes suitability for differing transport layer technologies, Investigations on proposed expanded scope DSCP stripping on the network, ECT(0) or ECT(1)
* *1 hour* Looking at packet interception with libpcap -> can strip most of the data we dont need before analysis
* *0.5 hours* Draft basic requirements

### 9 Oct 2020

* *1 hour* Reading DSCP modification paper "Towards a Middlebox Policy Taxonomy:Path Impairments"
* *1 hour* Reading Enabling Internet wide deployment of explicit congestion notification
* *0.5 hours* Revision of network programming in C "UNIX® Network Programming Volume 1, Third Edition: The Sockets Networking API"
* *1 hour* Reading "Measuring Interactions Between Transport Protocols and Middleboxes"

## Week 3

### 12 Oct 2020
* *1.5 hours* Work on prototype HTTP
* *1 hour* Resolving issue with ECN enablement

### 13 Oct 2020
* *0.5 hours* Refine requirements towards user stories

### 14 Oct 2020
* *1.5 hours* writing tcp dump clone + refactor proto + ipv6 support

### 15 Oct 2020
* *1 hour* meeting with advisor
* *5 hours* threading tcp dump clone + writing component api, debugging ipv6 support

### 16 Oct 2020
* *5 hours* Threaded libnetfilter component

### 18 Oct 2020
* *2 hours* Debugging pcap context switch
* *1 hours* writing in partial application of altering TOS bits of ipv4 header

## Week 4

### 21 Oct 2020
* *3 hours* Rough file parser and tweaks to alteration of TOS bits



### 22 Oct 2020

* *0.5 hours* Meeting with advisor
* *2 hours* Various refactorings, fixing memory leaks and invalid memory accesses
* *2 hours* fixing synchronisation issue with jit packet modifier
* *1 hour* implement proper ECN negotiation with jit packet modifier
* *0.5 hours* refactoring output file structure
* *0.5 hours* fixing ECT(0) bug

### 23 Oct 2020

* *4 hours* raw sockets traceroute implementation TCP
* *2 hours* initial work on ntp client

# Week 5

### 28 Oct 2020

* *0.5 hours* Administriva shuffle

### 29 Oct 2020

* *1 hour*  meeting with advisor
* *4 hours* debugging ntp/udp checksum issue
* *2 hours* Work on ntp traceroute implementation

### 30 Oct 2020

* *0.5 hours* implement solution to ntp/udp checksum issue
* *4 hours* working on iterative dns

### 5 Nov 2020

* *1 hour* Meeting with advisor
* *2 hours* Quic configuration on local machine
* *1 hour* Analysis on how to perform iterative dns
* *2 hours* Work on iterative dns

### 6 Nov 2020
* *4 hours* Work on iterative dns
* *2 hours* Work on iterative DNS bug
* *1 hours* Work refactoring DNS code

<!--- 
### 19 Oct 2019

* *4 hours* Read the project guidance notes
* *0.5 hour* Created GitLab repository and cloned the cookiecutter for the projects
* *1 hour* Modified dissertation template, compiled  

## 20 Oct 2019

* *1 hour* meeting with supervisor
* *2 hours* writing initial version of test harness

--->
