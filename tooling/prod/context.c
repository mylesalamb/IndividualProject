#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"

const char *str_proto[] = {
    "TCP",
    "NTP_UDP",
    "NTP_TCP",
    "DNS_UDP",
    "DNS_TCP",
    "QUIC",
    "TCP_PROBE",
    "NTP_UDP_PROBE",
    "NTP_TCP_PROBE",
    "DNS_UDP_PROBE",
    "DNS_TCP_PROBE",
    "QUIC_PROBE",
};

int ip_ver_str(char *host) {
  if (!host)
    return 0;

  return strchr(host, '.') ? AF_INET : AF_INET6;
}

/**
 * Get a string that represents a connection context
 * formatted wrt each protocol implemented
 */
void get_context_str(struct connection_context_t *ctx, char *dst)
{
        if (!dst)
                return;

        if (!ctx)
        {
                *dst = '\0';
                return;
        }

        // do some stuff that actually generates the sring that we want
        sprintf(dst, "%s-%s-%02x.pcap", ctx->host, str_proto[ctx->proto], ctx->flags);
}
