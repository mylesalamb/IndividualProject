#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

#include "parser.h"

static struct transaction_node_t *parse_transaction(char *buff);
static struct transaction_node_t *transaction_node_init();

#define HTTP_REQ "GET /index.html HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
const size_t req_len = strlen(HTTP_REQ);

struct transaction_list_t *fget_transactions(char *filename)
{
        FILE *fhandle = fopen(filename, "r");
        char buff[256];

        if (!fhandle)
        {
                perror("parser: open file");
                return NULL;
        }
                

        while (fgets(buff, sizeof(buff), fhandle) != NULL)
        {
                printf("Get buff\n");
                struct transaction_node_t *transac = parse_transaction(buff);
        
        }

        return NULL;
}

static
struct transaction_node_t *parse_transaction(char *buff){

        int len;
        char *lptr, *rptr;
        char *proto, *host;
        uint8_t tos;

        if(!buff)
                return NULL;
        
        struct transaction_node_t *transac = transaction_node_init();
        if(!transac)
        {
                perror("parse_transac:malloc");
                goto fail;
        }
                
        lptr = buff;
        rptr = buff;

        // parse ip addr
        while(!isspace(*rptr))
                rptr++;

        len = rptr - lptr + 2; // length + null char
        host = malloc(len * sizeof(char));
        if(!host){
                perror("parse_transac:malloc");
                goto fail;
        }

        strncpy(host, lptr, len-1);
        host[len-1] = '\0';

        transac->ctx->host = host;
        
        // skip spaces
        lptr = rptr;
        while(isspace(*lptr))
                lptr++;

        rptr = lptr;

        // parse tos
        rptr = lptr+2;
        // get two byte tos field
        tos = strtol(lptr, NULL, 16);
        
        // skip spaces
        lptr = rptr;
        while(isspace(*lptr))
                lptr++;

        rptr = lptr;

        // parse proto
        while(isalpha(*rptr))
                rptr++;

        len = rptr - lptr + 1; // length + null char
        proto = malloc(len * sizeof(char));
        if(!proto)
                goto fail;

        strncpy(proto, lptr, len-1);
        proto[len-1] = '\0';
        
        transac->ctx->host = host;
        //transac->ctx->proto = proto;
        transac->ctx->port = 6000;

        // handle different request types
        if(!strcmp(proto, "TCP"))
        {
                // get webserver name on line to format request properly
                char ws[128];

                lptr = rptr;
                while(isspace(*lptr))
                        lptr++;
                rptr = lptr;
                while(!isspace(*rptr))
                        rptr++;

                // prepare ws for format
                strncpy(ws, lptr, rptr - lptr + 1);
                ws[rptr - lptr] = '\0';

                len = req_len + (rptr - lptr);
                char *request = malloc(sizeof(char) * len);
                sprintf(request, HTTP_REQ, ws);

                transac->request = request;
        }


        printf("parsed vals ->\n\thost = %s\n\tproto = %s\n\ttos = %x\n", host, proto, tos);
        
        return transac;
fail:
        free(transac);
        return NULL;

}

static
struct transaction_node_t *transaction_node_init()
{
        struct transaction_node_t *ret;
        struct connection_context_t *ctx;

        ret = malloc(sizeof(struct transaction_node_t));
        ctx = malloc(sizeof(struct connection_context_t));
        if(!ret || !ctx)
                goto fail;

        ret->ctx = ctx;

        return ret;
fail:
        free(ret);
        free(ctx);
        return NULL;
}

void transaction_node_free(struct transaction_node_t *arg)
{
        if(!arg)
                return;
        
        free(arg->ctx->host);
        free(arg->request);
        free(arg);
}