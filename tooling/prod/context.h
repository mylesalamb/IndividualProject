#ifndef CONTEXT_H
#define CONTEXT_H 1

#include <stdint.h>

// Make ordering clear because we use these in jump tables
enum conn_proto {
	TCP  			= 0,
	NTP_UDP  		= 1,
	NTP_TCP			= 2,
	DNS_UDP  		= 3,
	DNS_TCP			= 4,
	QUIC 			= 5,
	TCP_PROBE 		= 6,
	NTP_UDP_PROBE 	= 7,
	NTP_TCP_PROBE	= 8,
	DNS_UDP_PROBE 	= 9,
	DNS_TCP_PROBE 	= 10,
	QUIC_PROBE 		= 11
};

// flags for additional fields
// TCP has slightly more complex interactions with
// the network so we can poke and prod to see if anything interesting happens
#define TCP_MARK_CONTROL (1 << 0)
#define TCP_TEST_ECE (1 << 1) 


struct connection_context_t
{
    char *host;
    enum conn_proto proto;
    int port;

    // addtional flags for managing connection at runtime
    uint8_t flags;
    uint8_t additional;
};

void get_context_str(struct connection_context_t *ctx, char *dst);


#endif
