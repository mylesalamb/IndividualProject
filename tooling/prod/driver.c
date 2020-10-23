#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "netinject.h"
#include "connector.h"
#include "pcapture.h"
#include "context.h"
#include "parser.h"

static void print_usage();
static void dispatch_req(struct transaction_node_t *transac,
                         struct nf_controller_t *nfc,
                         struct pcap_controller_t *pc);

int main(int argc, char **argv)
{

        char *alias = NULL;
        char *infile = NULL;
        char arg;

        while ((arg = getopt(argc, argv, "a:f:hv")) != -1)
        {
                switch (arg)
                {
                case 'a':
                        alias = optarg;
                        break;

                case 'f':
                        infile = optarg;
                        break;
                case 'h':
                        print_usage();
                        return EXIT_SUCCESS;
                        break;
                case '?':
                        print_usage();
                        return EXIT_FAILURE;
                        break;
                }
        }

        if (!infile)
        {
                printf("Must provide input file\n");
                return EXIT_FAILURE;
        }

        struct transaction_list_t *transactions = fget_transactions(infile);
        if (!transactions)
        {
                perror("infile parse error");
                return EXIT_FAILURE;
        }

        struct pcap_controller_t *pc = pcap_init(alias);
        struct nf_controller_t *nf = nf_init();

        struct transaction_node_t *cursor = transactions->head;
        while (cursor)
        {
                dispatch_req(cursor, nf, pc);
                cursor = cursor->next;
        }

        pcap_free(pc);
        nf_free(nf);

        transaction_list_free(transactions);

        printf("Complete\n");
        return EXIT_SUCCESS;
}

static void dispatch_req(struct transaction_node_t *transac,
                         struct nf_controller_t *nfc,
                         struct pcap_controller_t *pc)
{
        if (!transac || !transac->ctx)
                return;

        pcap_push_context(pc, transac->ctx);
        pcap_wait_until_rdy(pc);

        nf_push_context(nfc, transac->ctx);
        nf_wait_until_rdy(nfc);

        if (!strcmp(transac->ctx->proto, "TCP"))
        {
                printf("dispatch:tcp\n"
                       "with args:\n%s\n%s\n",
                       transac->ctx->host, transac->request);
                send_tcp_http_request(transac->request, transac->ctx->host, 6000);
        }
        else
        {
                perror("dispatch:unrecognised protocol");
        }

        pcap_close_context(pc);
        nf_close_context(nfc);
}

static void print_usage()
{

        printf("ECN Detector usage:\n"
               "\t-a alias to prefix to outputted file names\n"
               "\t-f input file name containing transactions to carry out\n");
}
