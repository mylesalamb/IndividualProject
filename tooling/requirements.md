# Project requirements

## Functional Requirements

* Should take an input file of client IP Addrs, no jit resolution because
  we want to avoid DNS load balancers to start connections with
* Should output data relating to the characteristics discovered of the connection
	- Outputting to a text file amenable to further analysis

* Supports different operating modes
	- TCP vs Quic
	- NTP vs HTTP
	- DSCP test
	- ECT(0) / ECT(1)

* Capability to operate over IPv6 and IPv4

### Connection establishment

* Supports ECN capable connections given suitable host configurations
* Supports a variety of transport layer protocls TCP, TLS, Quic, UDP(DNS || NTP)
* Detection of when an ECN capable connection has been established
* Detection of the modification of ECT codepoints -> approximating removal location on network path
	* Resolving to approximate AS number of the removal
* Detection of the modification of DSCP header 

## Non functional requirements

* Operate as a command line tool
* Capability to operate over large datasets ~100,000 samples
