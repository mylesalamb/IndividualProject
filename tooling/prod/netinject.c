#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>

#include "netinject.h"

static void *nf_controller(void *arg);
static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *msg, struct nfq_data *pkt, void *data);

struct nf_controller_t *nf_init()
{
        pthread_t th;
        struct nf_controller_t *nfc;

        nfc = malloc(sizeof(struct nf_controller_t));
        if (!nfc)
                return NULL;

        pthread_mutex_init(&nfc->mtx, NULL);
        pthread_cond_init(&nfc->cv, NULL);
        pthread_cond_init(&nfc->rdy, NULL);

        if (!(nfc->nfq_handle = nfq_open()))
        {
                perror("nf:nf_open_fail");
                return NULL;
        }

        if (nfq_bind_pf(nfc->nfq_handle, AF_INET) < 0)
        {
                perror("nf:nf_bind_fail");
                return NULL;
        }

        if (!(nfc->queue = nfq_create_queue(nfc->nfq_handle, 0, &packet_callback, NULL)))
        {
                perror("Error in nfq_create_queue()");
                return NULL;
        }

        if (nfq_set_mode(nfc->queue, NFQNL_COPY_PACKET, 0xffff) < 0)
        {
                perror("Could not set packet copy mode");
                return NULL;
        }

        nfc->nl_handle = nfq_nfnlh(nfc->nfq_handle);
        nfc->fd = nfnl_fd(nfc->nl_handle);

        // Put the socket in non-blocking mode:
        if (fcntl(nfc->fd, F_SETFL, fcntl(nfc->fd, F_GETFL) | SOCK_NONBLOCK) < 0)
        {
                perror("nf:socket");
                return NULL;
        }

        if (pthread_create(&nfc->th, NULL, &nf_controller, nfc))
        {
                perror("netinject:thread_create");
                return NULL;
        }

        return nfc;
}

static void *nf_controller(void *arg)
{
        struct nf_controller_t *nfc = (struct nf_controller_t *)arg;
        int res;
        char buf[4096];

        pthread_mutex_lock(&nfc->mtx);
        nfc->rdy_flag = true;
        pthread_mutex_unlock(&nfc->mtx);
        pthread_cond_signal(&nfc->rdy);

        while (1)
        {
                pthread_mutex_lock(&nfc->mtx);
                while (!nfc->controller_exit && !nfc->ctx)
                {
                        pthread_cond_wait(&nfc->cv, &nfc->mtx);
                }

                if (nfc->controller_exit)
                {
                        pthread_mutex_unlock(&nfc->mtx);
                        break;
                }
                pthread_mutex_unlock(&nfc->mtx);

                // connection_exit false -> we definitely know that the conneciton
                // is done because requests have been sent/modified
                while ((res = recv(nfc->fd, buf, sizeof(buf), 0)) && res > 0)
                        nfq_handle_packet(nfc->nfq_handle, buf, res);

                
        }

        return NULL;
}

void nf_push_context(struct nf_controller_t *nfc, struct connection_context_t *ctx)
{
        // this is exactly the same as netcap, possibillity to refactor? struct component {synchro, pcap || netfilter}?
        pthread_mutex_lock(&nfc->mtx);
        while (nfc->ctx)
                pthread_cond_wait(&nfc->cv, &nfc->mtx);
        nfc->ctx = ctx;
        pthread_mutex_unlock(&nfc->mtx);
        pthread_cond_signal(&nfc->cv);
}

void nf_wait_until_rdy(struct nf_controller_t *nfc)
{
        pthread_mutex_lock(&nfc->mtx);
        while (!nfc->rdy_flag)
                pthread_cond_wait(&nfc->cv, &nfc->mtx);
        nfc->rdy_flag = false;
        pthread_mutex_unlock(&nfc->mtx);
}

void nf_free(struct nf_controller_t *nfc)
{
        pthread_mutex_lock(&nfc->mtx);
        nfc->connection_exit = true;
        nfc->controller_exit = true;
        pthread_mutex_unlock(&nfc->mtx);
    
        pthread_join(nfc->th, NULL);

        pthread_mutex_destroy(&nfc->mtx);
        pthread_cond_destroy(&nfc->rdy);
        pthread_cond_destroy(&nfc->cv);

        nfq_destroy_queue(nfc->queue);
        nfq_close(nfc->nfq_handle);
        free(nfc);
}

static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *msg, struct nfq_data *pkt, void *data)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *header;

        if (header = nfq_get_msg_packet_hdr(pkt))
                id = ntohl(header->packet_id);

        unsigned char *pktData;

        int len = nfq_get_payload(pkt, &pktData);

        printf("data[ %d ]:\n", len);

        int i;
        for (i = 0; i < len; i++)
                printf("%2d 0x%02x %3d %c\n", i, pktData[i], pktData[i], pktData[i]);

        printf("\n");

        return nfq_set_verdict(queue, id, NF_ACCEPT, len, pktData);
}