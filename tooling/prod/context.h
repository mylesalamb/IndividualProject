#ifndef CONTEXT_H
#define CONTEXT_H 1

#include <stdint.h>

struct connection_context_t
{
    char *host;
    char *proto;
    int port;
    // tos mask for net inject -> proto and flags decide exact action
    uint8_t flags;
};


#endif