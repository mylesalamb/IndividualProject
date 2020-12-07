#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connector.h"
#include "context.h"
#include "netinject.h"
#include "parser.h"
#include "pcapture.h"

#include "lsquic.h"

static void print_usage();
static void dispatch_req(struct transaction_node_t *transac,
                         struct nf_controller_t *nfc,
                         struct pcap_controller_t *pc);

static int dispatch_web(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc);
static int dispatch_dns(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc);
static int dispatch_ntp(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc);

static int (*transac_disaptch[])(struct transaction_node_t *transac,
                                 struct nf_controller_t *nfc,
                                 struct pcap_controller_t *pc) =
                                {
                                        &dispatch_web,
                                        &dispatch_dns,
                                        &dispatch_ntp
                                };

int main(int argc, char **argv)
{

        char *alias = NULL;
        char *infile = NULL;
        char *outdir = "data";
        char arg;

        while ((arg = getopt(argc, argv, "a:f:d:hv")) != -1)
        {
                switch (arg)
                {
                case 'a':
                        alias = optarg;
                        break;

                case 'f':
                        infile = optarg;
                        break;
                case 'd':
                        outdir = optarg;
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
                fprintf(stderr, "must provide input file\n");
                return EXIT_FAILURE;
        }

        if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
        {
                fprintf(stderr, "lsquic:global_init\n");
                exit(EXIT_FAILURE);
        }
        else
        {
                printf("quic started properly\n");
        }

        struct transaction_list_t *transactions = fget_transactions(infile);
        if (!transactions)
        {
                fprintf(stderr, "infile parse error\n");
                return EXIT_FAILURE;
        }

        struct pcap_controller_t *pc = pcap_init(alias, outdir);
        struct nf_controller_t *nf = nf_init();

        struct transaction_node_t *cursor = transactions->head;
        while (cursor)
        {
                dispatch_req(cursor, nf, pc);
                cursor = cursor->next;
        }

        pcap_free(pc);
        nf_free(nf);
        lsquic_global_cleanup();

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

        transac_disaptch[transac->type](transac, nfc, pc);
}


static int dispatch_web(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc)
{
        return 0;
}

static int dispatch_dns(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc)
{
        int ecn;

        // todo add tcp stuff
        // transac->ctx->proto = DNS_TCP;
        // for(ecn = 0; ecn < 4; ecn++)
        // {
        //         transac->ctx->flags = ecn;

        //         pcap_push_context(pc, transac->ctx);
        //         pcap_wait_until_rdy(pc);

        //         nf_push_context(nfc, transac->ctx);
        //         nf_wait_until_rdy(nfc);

        //         send_tcp_dns_request(transac->ctx->host, transac->request,
        //                              transac->ctx->port);

        //         pcap_close_context(pc);
        //         nf_close_context(nfc);
        // }

        // transac->ctx->proto = DNS_UDP;
        // for(ecn = 0; ecn < 4; ecn++)
        // {
        //         transac->ctx->flags = ecn;

        //         pcap_push_context(pc, transac->ctx);
        //         pcap_wait_until_rdy(pc);

        //         nf_push_context(nfc, transac->ctx);
        //         nf_wait_until_rdy(nfc);

        //         send_udp_dns_request(transac->ctx->host, transac->request,
        //                              transac->ctx->port);

        //         pcap_close_context(pc);
        //         nf_close_context(nfc);
        // }

        transac->ctx->proto = DNS_UDP_PROBE;
        for (uint8_t ecn = 0; ecn < 1; ecn++)
        {
                transac->ctx->flags = ecn;

                pcap_push_context(pc, transac->ctx);
                pcap_wait_until_rdy(pc);

                nf_push_context(nfc, transac->ctx);
                nf_wait_until_rdy(nfc);

                send_udp_dns_probe(transac->ctx->host, transac->request, transac->ctx->port);
                pcap_close_context(pc);
                nf_close_context(nfc);
        }

        transac->ctx->proto = DNS_TCP_PROBE;
        for (ecn = 0; ecn < 1; ecn++)
        {
                transac->ctx->flags = ecn;

                pcap_push_context(pc, transac->ctx);
                pcap_wait_until_rdy(pc);

                nf_push_context(nfc, transac->ctx);
                nf_wait_until_rdy(nfc);

                send_tcp_dns_probe(transac->ctx->host, transac->request, transac->ctx->port);
        
                pcap_close_context(pc);
                nf_close_context(nfc);
        }

        

        return 0;
}

static int dispatch_ntp(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc)
{
        int ecn;

        // // todo add tcp stuff
        // transac->ctx->proto = NTP_TCP;
        // for(ecn = 0; ecn < 4; ecn++)
        // {
        //         transac->ctx->flags = ecn;

        //         pcap_push_context(pc, transac->ctx);
        //         pcap_wait_until_rdy(pc);

        //         nf_push_context(nfc, transac->ctx);
        //         nf_wait_until_rdy(nfc);

        //         send_tcp_ntp_request(transac->ctx->host,
        //                              transac->ctx->port);

        //         pcap_close_context(pc);
        //         nf_close_context(nfc);
        // }

        // transac->ctx->proto = DNS_UDP;
        // for(ecn = 0; ecn < 4; ecn++)
        // {
        //         transac->ctx->flags = ecn;

        //         pcap_push_context(pc, transac->ctx);
        //         pcap_wait_until_rdy(pc);

        //         nf_push_context(nfc, transac->ctx);
        //         nf_wait_until_rdy(nfc);

        //         send_udp_ntp_request(transac->ctx->host,
        //                              transac->ctx->port);

        //         pcap_close_context(pc);
        //         nf_close_context(nfc);
        // }

        transac->ctx->proto = NTP_UDP_PROBE;
        for (uint8_t ecn = 0; ecn < 3; ecn++)
        {
                transac->ctx->flags = ecn;

                pcap_push_context(pc, transac->ctx);
                pcap_wait_until_rdy(pc);

                nf_push_context(nfc, transac->ctx);
                nf_wait_until_rdy(nfc);

                send_udp_ntp_probe(transac->ctx->host, transac->ctx->port);
                pcap_close_context(pc);
                nf_close_context(nfc);
        }

        transac->ctx->proto = DNS_TCP_PROBE;
        for (ecn = 0; ecn < 3; ecn++)
        {
                transac->ctx->flags = ecn;

                pcap_push_context(pc, transac->ctx);
                pcap_wait_until_rdy(pc);

                nf_push_context(nfc, transac->ctx);
                nf_wait_until_rdy(nfc);

                send_tcp_ntp_probe(transac->ctx->host, transac->ctx->port);
        
                pcap_close_context(pc);
                nf_close_context(nfc);
        }

        return 0;
}


static void print_usage()
{

        printf("ECN Detector usage:\n"
               "\t-a alias to prefix to outputted file names\n"
               "\t-f input file name containing transactions to carry out\n"
               "\t-d output directory name");
}
