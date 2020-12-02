#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "netinject.h"
#include "connector.h"
#include "pcapture.h"
#include "context.h"
#include "parser.h"

#include "lsquic.h"


static void print_usage();
static void dispatch_req(struct transaction_node_t *transac,
                         struct nf_controller_t *nfc,
                         struct pcap_controller_t *pc);

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

        pcap_push_context(pc, transac->ctx);
        pcap_wait_until_rdy(pc);

        nf_push_context(nfc, transac->ctx);
        nf_wait_until_rdy(nfc);

        if (!strcmp(transac->ctx->proto, "TCP"))
        {

                printf("dispatch:tcp\n"
                       "with args:\n%s\n%s\n",
                       transac->ctx->host, transac->request);

                send_tcp_http_request(
                    transac->ctx->host,
                    transac->request,
                    transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "TCPPROBE"))
        {
                printf("dispatch:tcpprobe\n"
                       "with args:\n%s\n",
                       transac->ctx->host);
                send_tcp_http_probe(transac->ctx->host, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "NTPUDP"))
        {
                printf("dispatch:ntp\n"
                       "with args:\n%s\n",
                       transac->ctx->host);
                send_udp_ntp_request(transac->ctx->host, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "NTPUDPPROBE"))
        {
                printf("dispatch:ntpprobe\n"
                       "with args:\n%s\n",
                       transac->ctx->host);
                send_udp_ntp_probe(transac->ctx->host, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "NTPTCP"))
        {
                printf("dispatch:ntp\n"
                       "with args:\n%s\n",
                       transac->ctx->host);
                send_tcp_ntp_request(transac->ctx->host, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "NTPTCPPROBE"))
        {
                printf("dispatch:ntpprobe\n"
                       "with args:\n%s\n",
                       transac->ctx->host);
                send_tcp_ntp_probe(transac->ctx->host, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "DNSUDP"))
        {
                printf("dispatch:dns(udp)\n"
                       "with args:\n%s\n%s\n",
                       transac->ctx->host, transac->request);
                send_udp_dns_request(transac->ctx->host, transac->request, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "DNSTCP"))
        {
                printf("dispatch:dns tcp\n"
                       "with args:\n%s\n%s\n",
                       transac->ctx->host, transac->request);
                send_tcp_dns_request(transac->ctx->host, transac->request, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "DNSUDPPROBE"))
        {
                printf("dispatch:dns(udp)\n"
                       "with args:\n%s\n%s\n",
                       transac->ctx->host, transac->request);
                send_udp_dns_probe(transac->ctx->host, transac->request, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "DNSTCPPROBE"))
        {
                printf("dispatch:dns tcp\n"
                       "with args:\n%s\n%s\n",
                       transac->ctx->host, transac->request);
                send_tcp_dns_probe(transac->ctx->host, transac->request, transac->ctx->port);
        }
        else if (!strcmp(transac->ctx->proto, "QUIC"))
        {
                printf("dispatch:quic udp\n"
                       "with args:\n%s\n%s", transac->ctx->proto, transac->request);
                send_quic_http_request(transac->ctx->host, transac->request, transac->ctx->port, transac->ctx->flags & 0x03);
        }
        else if (!strcmp(transac->ctx->proto, "QUICPROBE")){
                printf("dispatch:quicprobe udp\n"
                       "with args:\n%s\n%s", transac->ctx->proto, transac->request);
                send_quic_http_probe(transac->ctx->host, transac->request, transac->ctx->port, transac->ctx->flags & 0x03);
        }
        else
        {
                fprintf(stderr, "dispatch:unrecognised protocol\n");
        }

        pcap_close_context(pc);
        nf_close_context(nfc);
}

static void print_usage()
{

        printf("ECN Detector usage:\n"
               "\t-a alias to prefix to outputted file names\n"
               "\t-f input file name containing transactions to carry out\n"
               "\t-d output directory name");
}
