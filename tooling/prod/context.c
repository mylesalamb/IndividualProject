#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "context.h"

const char *str_proto[] = {
	"TCP",  	
	"NTP",  	
	"DNS_UDP",
	"DNS_TCP",	
	"QUIC", 	
	"TCP_PROBE",
	"NTP_PROBE",
	"DNS_UDP_PROBE",
	"DNS_TCP_PROBE", 	
	"QUIC_PROBE", 		
	"INVALID"
};

/**
 * Get a string that represents a connection context
 * formatted wrt each protocol implemented
 */
void get_context_str(struct connection_context_t *ctx, char *dst)
{
        if(!dst)
			return;
        
        if (!ctx){
			*dst = '\0';
			return;
		}

		// do some stuff that actually generates the sring that we want

		sprintf(dst,"%s-%s-%02x.pcap",ctx->host, str_proto[ctx->proto], ctx->flags);
        
}

enum conn_proto str_to_proto(char *arg)
{
	if(!arg)
	{
		fprintf(stderr, "str_to_proto:null");
		return INVALID;
	}

	// this one chain allows us to use jump tables everywhere else

	if(!strcmp(arg, "TCP"))
		return TCP;

	if(!strcmp(arg, "NTPUDP"))
		return NTP_UDP;

	if(!strcmp(arg, "NTPTCP"))
		return NTP_TCP;

	if(!strcmp(arg, "DNSTCP"))
		return DNS_TCP;

	if(!strcmp(arg, "DNSUDP"))
		return DNS_UDP;

	if(!strcmp(arg, "QUIC"))
		return QUIC;

	if(!strcmp(arg, "TCPPROBE"))
		return TCP_PROBE;

	if(!strcmp(arg, "NTPTCPPROBE"))
		return NTP_TCP_PROBE;

	if(!strcmp(arg, "NTPUDPPROBE"))
		return NTP_UDP_PROBE;

	if(!strcmp(arg, "DNSUDPPROBE"))
		return DNS_UDP_PROBE;

	if(!strcmp(arg, "DNSTCPPROBE"))
		return DNS_TCP_PROBE;

	if(!strcmp(arg, "QUICPROBE"))
		return QUIC_PROBE;
		
	return INVALID;
}
