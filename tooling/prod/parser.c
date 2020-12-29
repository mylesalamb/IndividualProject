#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

#include "parser.h"
#include "context.h"
#include "log.h"

#ifndef UNIT_TEST
static struct transaction_node_t *parse_transaction(char *buff);
static struct transaction_node_t *transaction_node_init();
static struct transaction_list_t *transaction_list_init();
static void transaction_list_insert(struct transaction_list_t *lst, struct transaction_node_t *node);
static void transaction_node_free(struct transaction_node_t *arg);
#endif

extern const char *str_transac_type[];

enum transac_type str_to_transac_type(char *arg)
{
        if (!arg)
                return INVALID;

        for (int i = 0; i < (sizeof(str_transac_type) / sizeof(str_transac_type[0])); i++)
        {
                if (!strcmp(str_transac_type[i], arg))
                        return i;
        }

        return INVALID;
}

struct transaction_list_t *fget_transactions(char *filename)
{
        FILE *fhandle = fopen(filename, "r");
        char buff[256];

        if (!fhandle)
        {
                LOG_ERR("open file\n");
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
        enum transac_type type = INVALID;
        char *req = NULL;
        char *sep = " ";

        char *tok;
        if (!buff)
                return NULL;

        if (*buff == '#')
                return NULL;

        buff[strcspn(buff, "\n")] = 0;

        tok = strtok(buff, sep);
        if (!tok)
                goto fail;

        host = malloc(sizeof(char) * strlen(tok) + 1);
        if (!host)
                goto fail;
        strcpy(host, tok);

        tok = strtok(NULL, sep);
        if (!tok)
                goto fail;

        // this is the server type, if its not NTP we parse an additional field

        type = str_to_transac_type(tok);
        if (type == INVALID)
                goto fail;

        // All of these protos require some extra information
        // Just add to the rest of the line
        if (!strcmp("WEB", tok) || !strncmp("DNS", tok, 3))
        {
                tok = strtok(NULL, sep);
                if (!tok)
                        goto fail;

                req = malloc(sizeof(char) * (strlen(tok) + 1));
                if (!req)
                        goto fail;

                strcpy(req, tok);
        }

        ret = transaction_node_init();

        if (!ret)
                goto fail;

        // flags deffered to dispatch functions now
        ret->type = type;
        ret->ctx->flags = 0;
        ret->ctx->additional = 0;
        ret->ctx->host = host;
        ret->ctx->port = 6000;
        if (req)
        {

                ret->request = req;
        }
        LOG_INFO("Parse transac success\n");
        return ret;

fail:
        transaction_node_free(ret);
        free(host);
        if (req)
                free(req);
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

        if (node->type == INVALID)
                return;

        struct transaction_node_t **ptr = &lst->type_headers[node->type];

        node->next = *ptr;
        *ptr = node;

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
        ret->next = NULL;
        ret->request = NULL;

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

        for (struct transaction_node_t **head = arg->type_headers;
             head < &arg->type_headers[sizeof arg->type_headers / sizeof arg->type_headers[0]];
             head++)
        {

                struct transaction_node_t *cursor = *head;

                while (cursor)
                {
                        struct transaction_node_t *nxt = cursor->next;
                        transaction_node_free(cursor);
                        cursor = nxt;
                }
        }

        free(arg);
}

void transaction_node_free(struct transaction_node_t *arg)
{
        if (!arg)
                return;

        free(arg->ctx->host);
        free(arg->ctx);
        free(arg->request);
        free(arg);
}
