#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

#include "parser.h"

static struct transaction_node_t *parse_transaction(char *buff);
static struct transaction_node_t *transaction_node_init();
static struct transaction_list_t *transaction_list_init();
static void transaction_list_insert(struct transaction_list_t *lst, struct transaction_node_t *node);
static void transaction_node_free(struct transaction_node_t *arg);


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

        struct transaction_list_t *tlist = transaction_list_init();

        while (fgets(buff, sizeof(buff), fhandle) != NULL)
        {
                struct transaction_node_t *transac = parse_transaction(buff);
                if (transac)
                {
                        transaction_list_insert(tlist, transac);
                }
                else
                {
                        fprintf(stderr, "failed to parse transaction with line \"%s\"", buff);
                }
        }

        fclose(fhandle);

        return tlist;
}

static struct transaction_node_t *parse_transaction(char *buff)
{

        int len;
        char *lptr, *rptr;
        char *proto, *host;
        uint8_t tos;

        if (!buff)
                return NULL;

        struct transaction_node_t *transac = transaction_node_init();
        if (!transac)
        {
                perror("parse_transac:malloc");
                goto fail;
        }

        lptr = buff;
        rptr = buff;

        // parse ip addr
        while (!isspace(*rptr))
                rptr++;

        len = rptr - lptr + 1; // length + null char
        host = malloc(len * sizeof(char));
        if (!host)
        {
                perror("parse_transac:malloc");
                goto fail;
        }

        strncpy(host, lptr, len - 1);
        host[len - 1] = '\0';

        // skip spaces
        lptr = rptr;
        while (isspace(*lptr))
                lptr++;

        rptr = lptr;

        // parse tos
        rptr = lptr + 2;
        // get two byte tos field
        tos = strtol(lptr, NULL, 16);

        // skip spaces
        lptr = rptr;
        while (isspace(*lptr))
                lptr++;

        rptr = lptr;

        // parse proto
        while (isalpha(*rptr))
                rptr++;

        len = rptr - lptr + 1; // length + null char
        proto = malloc(len * sizeof(char));
        if (!proto)
                goto fail;

        strncpy(proto, lptr, len - 1);
        proto[len - 1] = '\0';

        transac->ctx->host = host;
        transac->ctx->proto = proto;
        transac->ctx->port = 6000;
        transac->ctx->flags = tos;

        // handle different request types
        if (!strcmp(proto, "TCP"))
        {
                // get webserver name on line to format request properly
                char ws[128];

                lptr = rptr;
                while (isspace(*lptr))
                        lptr++;
                rptr = lptr;
                while (!isspace(*rptr))
                        rptr++;

                // prepare ws for format
                strncpy(ws, lptr, rptr - lptr + 1);
                ws[rptr - lptr] = '\0';

                len = req_len + (rptr - lptr);
                char *request = malloc(sizeof(char) * len);
                sprintf(request, HTTP_REQ, ws);

                transac->request = request;
        }

        if(!strncmp(proto, "DNS", 3)){

                // get the record that we want to retrieve from the
                // dns infra


                lptr = rptr;
                while (isspace(*lptr))
                        lptr++;
                rptr = lptr;
                while (!isspace(*rptr))
                        rptr++;

                char *req = malloc(sizeof(char) * ((rptr - lptr) + 1));
                strncpy(req, lptr, rptr - lptr);
                req[rptr - lptr + 1] = '\0';
                transac->request = req;
                
        }

        // else
        // {
        //         perror("parse_transac:proto not supported");
        //         goto fail;
        // }

        printf("parsed vals ->\n\thost = %s\n\tproto = %s\n\ttos = %x\n", host, proto, tos);

        return transac;
fail:
        free(transac);
        return NULL;
}

static struct transaction_list_t *transaction_list_init()
{
        struct transaction_list_t *ret;
        ret = calloc(sizeof(struct transaction_list_t), 1);

        if (!ret)
                perror("transaction_list_init:malloc");

        return ret;
}

static void transaction_list_insert(struct transaction_list_t *lst, struct transaction_node_t *node)
{

        if (!lst || !node)
                return;

        // handle empty case
        if (!lst->head && !lst->tail)
        {

                node->next = NULL;
                lst->head = node;
                lst->tail = node;

                return;
        }

        // otherwise insert at tail

        lst->tail->next = node;
        lst->tail = node;

        return;
}

static struct transaction_node_t *transaction_node_init()
{
        struct transaction_node_t *ret;
        struct connection_context_t *ctx;

        ret = malloc(sizeof(struct transaction_node_t));
        ctx = malloc(sizeof(struct connection_context_t));
        if (!ret || !ctx)
                goto fail;

        ret->ctx = ctx;

        return ret;
fail:
        free(ret);
        free(ctx);
        return NULL;
}

void transaction_list_free(struct transaction_list_t *arg)
{
        if (!arg)
                return;

        struct transaction_node_t *cursor = arg->head;

        while (cursor)
        {
                struct transaction_node_t *nxt = cursor->next;
                transaction_node_free(cursor);
                cursor = nxt;
        }

        free(arg);
}

void transaction_node_free(struct transaction_node_t *arg)
{
        if (!arg)
                return;

        free(arg->ctx->host);
        free(arg->ctx->proto);
        free(arg->ctx);
        free(arg->request);
        free(arg);
}
