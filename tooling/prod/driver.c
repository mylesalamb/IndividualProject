#include <stdio.h>

#include "netinject.h"
#include "connector.h"
#include "pcapture.h"
#include "context.h"

int main(int argc, char **argv)
{
        char *host = "93.93.131.127";
        char *host2 = "13.224.86.144";

        struct connection_context_t context = {
            host, 1, 6000, 0};

        struct connection_context_t context2 = {
                host2, 1, 6000, 0
        };

        struct pcap_controller_t *pc = pcap_init();
        struct nf_controller_t *nf = nf_init();

        // execution of single request
        // produces a unique pcap file of the transaction

        printf("prepare pcap context\n");

        pcap_push_context(pc, &context);
        pcap_wait_until_rdy(pc);

        printf("prepare nf context\n");

        nf_push_context(nf, &context);
        printf("wait until nf ready\n");
        nf_wait_until_rdy(nf);
        printf("send req\n");

        send_tcp_http_request(
            "GET /teaching/index.html HTTP/1.1\r\nHost: www.csperkins.org\r\nConnection: close\r\n\r\n",
            "93.93.131.127",
            6000);

        printf("send req done\n");

        printf("close pcap context\n");
        pcap_close_context(pc);
        printf("close nf context\n");
        nf_close_context(nf);

        // start another connection and test for deadlocking states

        printf("prepare pcap context\n");

        pcap_push_context(pc, &context2);
        printf("wait until ready\n");
        pcap_wait_until_rdy(pc);

        printf("prepare nf context\n");

        nf_push_context(nf, &context2);
        printf("wait until nf ready\n");
        nf_wait_until_rdy(nf);

        printf("send next tcp req");

        send_tcp_http_request(
                "GET /index.html HTTP/1.1\r\nHost: www.neverssl.com\r\nConnection: close\r\n\r\n",
                "13.224.86.144",
                6000
        );

        // free the resources for capturing data

        pcap_free(pc);
        nf_free(nf);

        return 0;
}