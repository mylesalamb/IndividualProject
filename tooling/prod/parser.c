#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

#include "parser.h"

#ifndef UNIT_TEST
static struct transaction_node_t *parse_transaction(char *buff);
static struct transaction_node_t *transaction_node_init();
static struct transaction_list_t *transaction_list_init();
static void transaction_list_insert(struct transaction_list_t *lst, struct transaction_node_t *node);
static void transaction_node_free(struct transaction_node_t *arg);
#endif

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

unit_static struct transaction_node_t *parse_transaction(char *buff)
{
        struct transaction_node_t *ret = NULL;

        char *host = NULL;
        char *proto = NULL;
        char *sep = " ";
        uint8_t flags;

        char *tok;
        if (!buff)
                return NULL;

        tok = strtok(buff, sep);
        if (!tok)
                goto fail;

        host = malloc(sizeof(char) * strlen(tok) + 1);
        if (!host)
                goto fail;
        strcpy(host, tok);
        printf("host is %s\n", host);

        // Should be the TOS bits
        tok = strtok(NULL, sep);
        if (!tok)
                goto fail;

        flags = strtol(tok, NULL, 16);
        printf("flags are %d from buff %s\n", flags, tok);

        tok = strtok(NULL, sep);
        if (!tok)
                goto fail;

        proto = malloc(sizeof(char) * strlen(tok) + 1);
        if (!proto)
                goto fail;
        strcpy(proto, tok);
        printf("proto is %s\n", proto);

        ret = transaction_node_init();

        if (!ret)
                goto fail;

        ret->ctx->flags = flags;
        ret->ctx->host = host;
        ret->ctx->port = 6000;
        ret->ctx->proto = proto;

        // parse additional options
        if (!strncmp("TCP", proto, 3))
        {
                tok = strtok(NULL, sep);
                char *req = malloc(sizeof(char) * (strlen(tok) + req_len));
                sprintf(req, HTTP_REQ, tok);
                ret->request = req;
        }
        if (!strncmp("DNS", proto, 3))
        {
                tok = strtok(NULL, sep);
                char *req = malloc(sizeof(char) * strlen(tok) + 1);
                strcpy(req, tok);
                ret->request = req;
        }

        printf("got to end\n");
        return ret;

fail:
        transaction_node_free(ret);
        free(host);
        free(proto);
        return NULL;
}

unit_static struct transaction_list_t *transaction_list_init()
{
        struct transaction_list_t *ret;
        ret = calloc(sizeof(struct transaction_list_t), 1);

        if (!ret)
                perror("transaction_list_init:malloc");

        return ret;
}

unit_static void transaction_list_insert(struct transaction_list_t *lst, struct transaction_node_t *node)
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

unit_static struct transaction_node_t *transaction_node_init()
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
