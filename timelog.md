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
* *1 hour* meeting with advisor + prep
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

* *1 hours* Meeting with advisor + prep
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

* *0.5 hours* Administriva reorganising

### 29 Oct 2020

* *1 hour*  meeting with advisor + prep
* *4 hours* debugging ntp/udp checksum issue
* *2 hours* Work on ntp traceroute implementation

### 30 Oct 2020

* *0.5 hours* implement solution to ntp/udp checksum issue
* *4 hours* working on iterative dns

# Week 6

### 5 Nov 2020

* *1 hour* Meeting with advisor + prep
* *2 hours* Quic configuration on local machine
* *1 hour* Analysis on how to perform iterative dns
* *2 hours* Work on iterative dns

### 6 Nov 2020
* *4 hours* Work on iterative dns
* *2 hours* Work on iterative DNS bug
* *1 hours* Work refactoring DNS code

### 7 Nov 2020

* *1 hour* finish iterative dns
* *1hour* refactoring connector.c
* *1.5 hours* aws setup
* *1.5 hour* tinkering with provisioning systems (terraform, vagrant)
* *1 hour* work with image proviosiong (docker, vm images) -> docker images are not fun to work with
* *1.5 hours* work on terraform and packer

# Week 7

### 9 Nov 2020

* *2.5 hours* Finish up work on packer
* *1.5 hours* Work on jit packet modifications -> adapt to ipv6

### 10 Nov 2020

* *1 hour* Set up ntp dataset gatherer + adapt to ipv6


### 12 Nov 2020

* *1 hour* Brief work on methodology
* *0.5 hours* Small ammendments to installer script
* *1 hour* Advisor meeting + prep
* *3 hours* Work on TCP DNS
* *1 hour* Refactorings + initial test suite 

### 13 Nov 2020

* *3 hours* Attempt to resolve bug with test suite
* *2 hours* refactor file parser code
* *2 hours* Attempt to resolve memory leaks with DNS

### 15 Nov 2020

* *0.5 hours* Solve issue with test suite + At to CI
* *1.5 hours* Adapt ntp code to use IPv6
* *3 hours* Attempt to adapt ntp tracert code to IPv6
* *1.5 hours* Various refactorings

# Week 8

### 16 Nov 2020
* *2 hours* Refactorings in connector.c (protocol client code)
* *1.5 hours* Attempt to resolve issue with IPv6 raw sockets

### 17 Nov 2020

* *3 hours* Work on experiemntal methodology

### 18 Nov 2020

* *1 hour* implement pktinfo to capture ipv6 src addrs
* *1 hour* ipv4/ipv6 raw sockets impl

### 19 Nov 2020

* *5 hours* refactor/rewrite connector.c


### 20 Nov 2020

* *1.5 hours* Resolve issues with refactor (fix sendto port with rawsock)
* *1 hour* integrate lsquic into installer image
* *1 hour* make rawsock more robust / fix invalid memory accesses
* *1 hour* resolve issue with AWS (tx boxes are only useful for burst loads)
* *1 hour* Further research on terraform deploy script (jit vpc creation)

### 21 Nov 2020

* *2 hours* Resolve issues with IPv6 rawsock not sending
* *1.5 hours* Minor refactorings

# Week 9

## 25 Nov 2020

* *1 hour* Reading lsquic documentation
* *3 hours* Work on intial version of Quic connections
* *2 hour* Begin to integrate lsquic into installer script for cloud machines

## 26 Nov 2020

* *1 hour* Advisor meeting + prep
* *2 hours* Continue work with integrating quic
* *2 hours* Debug issues with wireshark and quic

## 27 Nov 2020

* *1.5 hours* Install wireshark from source

## 28 Nov 2020

* *1.5 hours* Change repo to submodule style
* *2 hours* Use lsquic tutorial to supplement connection code
* *2 hour* Identify bug introduced in lsquic, revert to previous lsquic release
* *2 hours* Begin work on integrating cron jobs onto amazon machine

## 29 Nov 2020

* *4 hours* Work on multi instance terraform
* *2 hours* Integrate packer output with terraform input

# Week 10

## 1 Dec 2020

* *4 hours* Work on Quic tracert

## 3 Dec 2020
* *1 hour* Advisor meeting + prep

## 4 Dec 2020

* *3 hours* Work on ethics approval files

## 6 Dec 2020

* *3 hours* Refactor use of strcmp to jump tables + Various minor refactorings
* *2 hours* Attempt to resolve bug with udp + tcp rawsockets

# Week 11

## 7 Dec 2020

* *3.5 hours* Solve bug with raw tracerts / switch compiler to clang

## 8 Dec 2020

* *3 hours* Refactor / tidy up tool output
* *3 hours* Tidy up installer script for deploy
* *1.5 hours* Resolve issues from preflight deploy

## 9 Dec 2020

* *1 hours* Tidy up delays -> make tool faster
* *2 hours* Resolve timing issue that caused segfault with tool

## 11 Dec 2020

* *3 hours* Improve timing through use of nanosleep
* *3 hours* Fix CI pipeline (Was left broken for a while)
* *1 hours* Tweaks to ethics documentation

## 12 Dec 2020

* *3 hours* Make pcap component much faster with immediate mode
* *2 hours* Begin to untether from specific ports

## 13 Dec 2020

* *2 hours* research pcap parsing libs
* *3 hours* Begin work on data analysis component
* *2 hours* Resolve issues with parsing quic files

# Week 12

## 15 Dec 2020

* *2 hours* Alter python polymorphism model to support file parsing model
* *2 hours* Begin to implement strategies for calculating statistics
* *2 hours* Fix latency issue with libpcap

## 16 Dec 2020

* *2.5 hours* Attempting to source participants from reddit + other user groups
* *1 hour* Refactor/improve makefile

## 17 Dec 2020

* *1 hour* Advisor meeting + prep
* *2 hours* Improve file handling under data analysis component

# Week 13

## 23 Dec 2020

* *5 hours* Re-implement terraform functionality properly, parameterise into terraform module

## 24 Dec 2020

* *3 hours* Un-tether network tool from using a singular port

## 24 Dec 2020

* *2 hours* Identify concurrency issue with network analysis tool, under small deplyoment

## 27 Dec 2020

* *1.5 hours* Continue trying to debug concurrency issue
* *1.5 hours* Start work on, on path TCP support
* *1 hour* Patch packer integration script after update

# Week 14

## 28 Dec 2020

* *2 hours* Begin collecting alexa top sites dataset
* *1 hour* Clear up small installer bugs from pre-deploy
* *1 hour* Update pre flight scripts

## 29 Dec 2020

* *2 hours* Various readability improvements in connector.c
* *0.5 hours* Remove down DNS resolvers from dataset
* *1.5 hours* More mork on fixing concurrency issues
* *1.5 hours* Attempt another pre-flight

## 30 Dec 2020

* *1 hour* Track down researce leak, fd in connector.c
* *1 hour* Tidy up memory management

## 31 Dec 2020

* *0.5 hours* Fix cron scheduling for deploy
* *1 hour* Fix occasional crash with IPv6 lookup

## 2 Jan 2021

* *1 hour* Continue trying to fix concurrency issue with components
* *1 hour* Various refactorings in connector.c

## 3 Jan 2021

* *3 hours* Fix additional memory leaks
* *2 hours* Continue with TCP path probe
* *1 hours* Contacting participants

# Week 15

## 4 Jan 2021

* *3 hours* Trial ARM support + debug signed char
* *2 hours* Writing Raspberry Pi installer script


## 5 Jan 2021
* *1.5 hours* Contacting participants

## 6 Jan 2021

* *2 hours* Identify IPv6 bug + attempt to fix, raw IPv6 tracert not recognising host response
* *4 hours* Finish on path tcp traceroute

## 7 Jan 2021

* *3 hours* Completely re-write concurrency model
* *1 hour* Implement timed wait for TCP acks in no response from host

## 8 Jan 2021

* *2.5 hours* Work on formatting datasets for tool + various shell scripts
* *1 hour* Contacting participants, getting consent forms

## 9 Jan 2021

* *1.5 hours* Patch CI again
* *1 hour* Add automated installers for deployment
* *2 hours* Contacting participants for consent forms

# Week 16
<!-- 11 - 17 -->
## 11 Jan 2021
* *1 hour* Advisor meeting + prep
* *2 hours* Deploy for automated hosts (AWS)
* *4 hours* Contacting participants 

## 12 Jan 2021
* *1.5 hours* Check in with automated tools and participants
* *1 hour* Deploy bugfix for IPv4 hosts and IPv6 dataset
* *1 hour* Fix for manual install 

## 13 Jan 2021
* *1.5 hours* Check in with automated tools and participants
* *1 hour* Add kill step for stalled aws machines

## 14 Jan 2021
* *1.5 hours* Check in with automated tools and participants

## 15 Jan 2021
* *1.5 hours* Check in with automated tools and participants

## 16 Jan 2021
* *1.5 hours* Check in with automated tools and participants
* *1.5 hours* Add strategy pattern from sniffing packets 



# Week 17
<!-- 18 - 24 -->

## 18 Jan 2021
* *1 hour* Advisor meeting + prep

## 23 Jan 2021

* *2 hours* Add more statistic calculations, does host TCP reset
* *1 hour* Nug fix for calculating what hop removed ECT codepoint
* *1.5 hours* Cumulative density function for TCP removal

## 24 Jan 2021

* *2 hours* Debrief participants
* *2 hours* Collect results from participants
* *2 hours* Data pruning, removing unsuccessfull traces

# Week 18
<!-- 25 - 31 -->

## 25 Jan 2021

* *1 hour* Advisor meeting + prep

## 26 Jan 2021

* *2 hours* Collect data from AWS hosts

# Week 19
<!-- 1 - 7  -->

## 1 Feb 2021

* *1 hour* Advisor meeting + prep

* *2 hours* Continue data analysis statistics
* *2 hours* Begin checkpointed data analysis implementation
* *1 hour* High level overview of data (check for interesting characteristics)
* *1 hour* Investigate Participant-1 data
* *1 hour* Call with participant one with followup questions

# Week 20
<!-- 8 - 14  -->

## 8 Feb 2021

* *1 hour* Advisor meeting + prep


# Week 21
<!-- 15 - 21 -->

## 19 Feb 2021

* *3 hours* Start writing basic dissertation structure





# Week 22

<!-- 22 - 28 -->

## 20 Feb 2021

* *4 hours* diss

## 22 Feb 2021

* *2 hours* Work on dissertation intro, and template some of background section
* *1 hour* Advisor meeting + prep
* *1 hour* implement guidance on dissert structure from advisor

## 26 Feb 2021

* *2 hours* Work on ICMP explanation in background

## 27th Feb 2021

* *2 hours* Work on dissertation design section
* *3 hours* Work on dissertation background section

## 28th Feb 2021

* *1 hour* Redo system architecture diagram for dissertation

# Week 23

<!-- 1 -- 7  -->

## 1 Mar 2021

* *1 hour* Advisor meeting + prep

## 3 Mar 2021

* *5 hours* Writing up experiemental methodology
* *1 hour* Plan out results section

## 6 Mar 2021

* *1 hour* Generate plotted host samples on earth map
* *3 hours* Work revising experimental methodology write up


# Week 24
<!-- 8 - 14 -->
## 8 Mar 2021
* *1.5 hours* Work on analysis section
* *3 hours* Work on implementation section

## 9 Mar 2021

* *1 hour* Begun writing results section, TCP adoption

## 10 Mar 2021

* *1 hour* Add extra detail to methodology
* *1 hour* Fix bug with TCP adoption
* *5 hours* Finish TCP ECN adoption section, add in other measurements from studies
* *2 hours* Small tweaks to background section

## 11 Mar 2021

* *2 hours* Parallelism refactor for data analysis tool -> run each instance in its own thread
* *0.5 hours* Placeholder abstract



# Week 25
<!-- 15 - 21 -->

## 16 Mar 2021

* *1 hour* Advisor meeting + prep
* *3 hours* Produce TCP bar charts for TCP strip data between hosts, write up surrounding content

## 17 Mar 2021

* *1.5 hours* Write up deployment notes in implementation section (packer and terraform programs)

## 19 Mar 2021

* *1 hour* Begin to write up quic section

## 20 Mar 2021

* *2 hours* Data analysis, checking statistical assumptions for IPv4 and IPv6 data (including background reading on stats)
* *1.5 Hours* Flesh out implementation section, "ip version remarking", and other notable "behaviours"
* *1.5 hours* Flesh out transport protocol dependant remarking section
* *1.5 hours* implement new data analysis statistics for ECT marked ICMP responses

## 21 Mar 2021

* *2 hours* Revise implementation section discussion of network analysis tool

# Week 26
<!-- 22 - 28 -->

## 24 Mar 2021

* *1 hours* Work on aesthetics / introduce data visualization of hops, 
* *1.5 hours* Write up abnormal results from Participant-1
* *1.5 hours* Graph on interface hop that Codepoint is removed + write up surrounding section
* *1.5 hours* Graph on TCP UDP comparison + surrounding write up

## 26 Mar 2021

* *1 hour* Small changes in section on UDP, grammar related
* *2 hours* Write up section on routers that mimick ToS

## 27 Mar 2021

* *2 hours* Finish up writing on routers tat mimic tos and include diagram methodology

## 28 Mar 2021

* *2 hours* Clarify in results sections what data is being used and where it came from, "selecting traces from x dataset"


# Week 27

## 29 Mar 2021

* *3 hours* Write up results on data from AS boundaries

## 31 Mar 2021

* *3 Hours* Tweak AS boundary calcualtions and write into dissertation 
* *2 Hours* Identify specific network interfaces that are clearing and write up

## 1 April 2021

* *1 Hour* As traversal graph
* *1 hour* Fix latex tables with long column names
* *1 hour* Summary for implementation section
* *2 hours* Discover and write up specific markup behaviours
* *3 hours* Add more detail to ECN under UDP section

## 2 April 2021

* *1 hour* Add detail to TCP UDP section
* *2 hours* Do device matching between udp and tcp traces, and writing up results into dissertation

* *1 hour* Write up conclusion
* *1 hour* Improve graph of hops figure so that it appears much clearer
* *2 hours* Begin redrafting first sections (abstract and intro)
* *1 hour* Remove subheadings + improve prose structure

## 3 April 2021

* *1 hour* tidy up experimental method + removing extrenous comments
* *1.5 hours* Add in why routers drop packets, flow better to ECN section
* *1.5 hours* Improve flow of implementation section

## 4 April 2021

* *1.5 hours* more work on implementation section, fleshing out explnation of deployment infra
* *3 hours* various small changes across sections to improve flow + less reliance on subheadings


## 5 April 2021

* *1 hour* Preparing appendices, ethics approval, consent forms and include within dissertation
* *1 hour* Add volunteer information to implementation section
* *2 hours* Work on per ect modification section in results
* *1 hour* Code for per ect modifcation section.

## 6 April 2021

* *1 hour* Write up specific remarking behaviour
* *1 hour* Code for specific remarking behaviour
* *2 hours* Relate results to previous papers + fill in references from zotero
* *1 hour* Track down RFCs to cite
* *1 hour* Finish up with statistics for IPv4 and IPv6 (confidence intervals)
* *1 hour* Proof read and grammar fixes

# Week 28

## 7 April 2021

* *8.5 hours* Spelling and grammar fixes

## 10 April 2021

* *2 hours* Additional spelling checking and
* *4 hours* Finish up with tooling documentation
* *1 hour* Restructure repository in preparation for submission

## 11 April 2021


* *1 hour* Small stylistic changes, making sure acronyms are first elaborated.
* *5 hours* create slides, and implement video


## 12 April 2021

* *2 hours* Small last minute changes to directory structure for submission, last minute referencing



