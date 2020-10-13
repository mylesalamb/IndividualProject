# User stories

As a: Researcher
I want to: Negotiate ECN capable TCP connections
So that: I can test connectivity with webservers when ECN is used

As a: Researcher
I want to: Negotatite non-ecn TCP connections
So that: I can test connectivity with webservers when ECN is not used

As a: Researcher
I want to: Negotatite ECN capable quic connections
So that: I can test connectivity with webservers when ECN is used

As a: Researcher
I want to: Negotiate non-ecn quic connections
So that: I can test connectivity with webservers when ECN is not used

As a: Researcher
I want to: To mark packets with either ECT0 or ECT1
So that: I can test differential characteristics when either codepoint is used

As a: Researcher
I want to: To mark packets with various DSCP markings
So that: I can test differential characteristics when they are used

As a: Researcher
I want to: To specify whether connections should use IPv4 or IPv6
So that: I can test differential when either version is used

As a: Researcher
I want to: Bulk specify a list of ip addresses and means to connect (proto, ip version, ECN + DSCP markings)
So that: so that i can bulk generate at once

As a: Researcher
I want to: Send ECN capable DNS requests
So that: I can analyse interactions with existing internet infrasructure with ECN

As a: Researcher
I want to: Send non-ECN capable DNS requests
So that: I can analyse interactions with existing internet infrastructure without ECN

As a: Researcher
I want to: Send ECN capable NTP requests
So that: I can analyse interactions with existing internet infrastructure with ECN

As a: Researcher
I want to: Send non-ECN capable NTP requests
So that: I can analyse interactions with existing internet infrastructure without ECN

As a: Researcher
I want to: capture network information on how packets are modified on the network
So that: I can perform analysis on what modifications occur under a given instance

As a: Researcher
I want to: Capture network traffic of connections
So that: I can perform analysis on the iteractions on the network with varying code points

As a: Researcher
I want to: Operate the tool as a command line tool
So that: I can feasibly use the tool on cloud instances