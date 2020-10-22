#ifndef CONTEXT_H
#define CONTEXT_H 1

struct connection_context_t
{
    char *host;
    char *proto;
    int port;
    // tos mask for net inject
    unsigned char flags;
};


#endif