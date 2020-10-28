*Note that the original version of this plan was implemented as github milestones but was discontinued as it proved cumbersome to work with*

# Week 1

- Setup of github
- CI/CD solution
- Familiarise with project guidance
- Background reading on landscape of ECN

# Week 2

- Background Reading ECN + DSCP
- Technology stack selection (Amazon EC2, implementation language C, posix set sockopt) -> revised to libnetfilter and libpcap
- Technology familiarisation

# Week 3

- Feasibility prototype (Unsuccessful) -> see revision from technology choice in week 2
- Produce requirements in form of user stories
- Begin work on final version of tool
    - basic component development for all required prototypes, libpcap and netfilter, file parser

# Week 4

- Finish implementing basic components (packet capture and modifier)

*protos are implied to work with ipv6 as well as ipv4 if applicable, and implied to have ECN and ECN-less functionality*
# Week 5


- Work on HTTP solution ->
    - send ECN / ECN-less connections
    - Revision (IPv6 shelfed to pre flight on aws)

- TCP Tracert should be done at this point

# Week 6

- Work on NTP Solution
- UDP Style traceroute

- AWS preflight moved to here -> accelerate IPv6 support,

- Begin Drafting methodology (may inform moving sourcing of datasets)

# Week 7

- Work on DNS solution
    - Non recursive DNS we want to probe the path and record ECN interactions
- Finish up work on methodology
# Week 8

- Work on Quic solution (cloudflares quic impl looks the most promising (best documented))
    - Note that UDP tracert is done
- Begin sourcing datasets (Particularly NTP as this takes time)
# Week 9

- Finish up quic configuration
- Buffer time for quic issues

# Week 10

- TLS configuration
- Pre-flight of deployment (Test with large dataset to check for issues before final)

# Week 11

- Buffer Time for delays
- Technical debt ahead of deployment

# Week 12

- Slight methodology adjustments
- Deployment of tool

# Week 13

- Collection and verification
- Begin data analysis

# Week 14

- Continue data analysis (lessened workload due to xmas period)

# Week 15

- No work planned

# Week 16

- Continue Data analysis

# Week 17

- Continue Data Analysis

# Week 18
# Week 19
# Week 20
# Week 21
# Week 22
# Week 23
# Week 24
# Week 25
# Week 26

# Week 27

- (26th) Project submission

