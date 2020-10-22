#ifndef PARSER_H
#define PARSER_H 1

#include "context.h"

struct transaction_node_t
{
    char * request;
    struct connection_context_t *ctx;
    
};

struct transaction_list_t
{
    struct transaction_node_t *head, *tail;
};


struct transaction_list_t *fget_transactions(char *filename);

#endif