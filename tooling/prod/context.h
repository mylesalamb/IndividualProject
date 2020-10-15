#ifndef CONTEXT_H
#define CONTEXT_H 1

struct connection_context_t
{
    char *host;
    int proto;
    int port;
    int flags;
};


#endif