#ifndef PARSER_H
#define PARSER_H 1

#include "test_config.h"
#include "context.h"

struct transaction_node_t
{
    struct transaction_node_t *next;
    
    char * request;
    struct connection_context_t *ctx;
};

struct transaction_list_t
{
    struct transaction_node_t *head, *tail;
};


struct transaction_list_t *fget_transactions(char *filename);
void transaction_list_free(struct transaction_list_t *arg);



#ifdef UNIT_TEST
struct transaction_node_t *parse_transaction(char *buff);
struct transaction_node_t *transaction_node_init();
struct transaction_list_t *transaction_list_init();
void transaction_list_insert(struct transaction_list_t *lst, struct transaction_node_t *node);
void transaction_node_free(struct transaction_node_t *arg);
#endif


#endif
