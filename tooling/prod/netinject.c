#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>

#include <linux/netfilter.h>
#include <linux/types.h>
#include <linux/ip.h>

#include <linux/tcp.h>
#include <linux/udp.h>

#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>

#include "netinject.h"

#define IS_ECN(x) (x & 0x03)

static void *nf_controller(void *arg);
static void nf_handle_conn(struct nf_controller_t *nfc);
static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *msg, struct nfq_data *pkt, void *data);

static int nf_handle_tcp(struct connection_context_t *ctx, uint8_t *payload, size_t len);
static int nf_handle_ntp(struct connection_context_t *ctx, uint8_t *payload, size_t len);

struct nf_controller_t *nf_init()
{
        struct nf_controller_t *nfc;

        nfc = malloc(sizeof(struct nf_controller_t));
        if (!nfc)
                return NULL;

        pthread_mutex_init(&nfc->mtx, NULL);
        pthread_cond_init(&nfc->cv, NULL);
        pthread_cond_init(&nfc->rdy, NULL);

        nfc->ctx = NULL;
        nfc->connection_exit = false;
        nfc->controller_exit = false;

        if (!(nfc->nfq_handle = nfq_open()))
        {
                perror("nf:nf_open_fail");
                return NULL;
        }

        if (!(nfc->queue = nfq_create_queue(nfc->nfq_handle, 0, &packet_callback, &nfc->ctx)))
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

bool nf_get_connection_exit(struct nf_controller_t *nfc)
{
        bool ret;
        pthread_mutex_lock(&nfc->mtx);
        ret = nfc->connection_exit;
        pthread_mutex_unlock(&nfc->mtx);
        return ret;
}

static void *nf_controller(void *arg)
{
        struct nf_controller_t *nfc = (struct nf_controller_t *)arg;

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
                else if (nfc->ctx)
                {
                        nfc->rdy_flag = true;
                        nfc->connection_exit = false;
                }
                pthread_mutex_unlock(&nfc->mtx);
                pthread_cond_signal(&nfc->cv);

                // connection_exit false -> we definitely know that the conneciton
                // is done because requests have been sent/modified

                nf_handle_conn(nfc);
        }

        return NULL;
}

static void nf_handle_conn(struct nf_controller_t *nfc)
{
        int res;
        char buf[4096];

        while (!nf_get_connection_exit(nfc))
        {
                while ((res = recv(nfc->fd, buf, sizeof(buf), 0)) && res > 0)
                        nfq_handle_packet(nfc->nfq_handle, buf, res);
        }

        pthread_mutex_lock(&nfc->mtx);
        nfc->ctx = NULL;
        pthread_mutex_unlock(&nfc->mtx);
}
void nf_close_context(struct nf_controller_t *nfc)
{
        pthread_mutex_lock(&nfc->mtx);
        nfc->connection_exit = true;
        nfc->ctx = NULL;
        pthread_mutex_unlock(&nfc->mtx);
        pthread_cond_signal(&nfc->cv);
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
        nfc->ctx = NULL;
        pthread_mutex_unlock(&nfc->mtx);
        pthread_cond_signal(&nfc->cv);

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
        struct connection_context_t *ctx = *(struct connection_context_t **)data;
        int id = 0, len = 0;
        struct nfqnl_msg_packet_hdr *ph;
        uint8_t *payload, ipver;
        
        ph = nfq_get_msg_packet_hdr(pkt);
        if (!ph)
        {
                perror("nf:packet_header");
                goto fail_no_pkt;
        }

        // id used by kernel
        id = ntohl(ph->packet_id);
        len = nfq_get_payload(pkt, &payload);

        // do dispatch for ipv6 or ipv4
        ipver = (*payload & 0xf0) >> 4;


        printf("ip version is %d", ipver); 

        if (!len)
        {
                perror("netinject:pkt len");
                goto fail;
        }


        if (!strncmp(ctx->proto, "TCP", 3))
        {
                 if(nf_handle_tcp(ctx, payload, len))
                        return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
        }
        else if (!strncmp(ctx->proto, "NTP", 3)){
                printf("Picked up ntp flow\n");
                if(nf_handle_ntp(ctx, payload, len))
                        return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
        }
        else if(!strncmp(ctx->proto, "DNS", 3)){
                printf("Picked up udp flow\n");
                if(nf_handle_ntp(ctx, payload, len))
                        return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
        }
        else
        {
                perror("netinject:proto not recognised -> nop");
                printf("proto was: %s", ctx->proto);
        }

        return nfq_set_verdict(queue, id, NF_ACCEPT, len, payload);

fail_no_pkt:
        return 0;
fail:
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}

static int nf_handle_ntp(struct connection_context_t *ctx, uint8_t *payload, size_t len)
{
        struct pkt_buff *pkt;
        struct udphdr *udp;
        struct iphdr *ip;

        pkt = pktb_alloc(AF_INET, payload, len, 0);

        ip = nfq_ip_get_hdr(pkt);
        nfq_ip_set_transport_header(pkt, ip);
        udp = nfq_udp_get_hdr(pkt);

        if(!udp){
                perror("netinjection:could not get udp packet");
                pktb_free(pkt);
                return -1;
        }

        ip->tos = ctx->flags;

        nfq_ip_set_checksum(ip);
        nfq_udp_compute_checksum_ipv4(udp,ip);

        memcpy(payload, pktb_data(pkt), len);
        pktb_free(pkt);

        return 0;

}

static int nf_handle_tcp(struct connection_context_t *ctx, uint8_t *payload, size_t len)
{

        struct pkt_buff *pkt;
        struct tcphdr *tcp;
        struct iphdr *ip;

        pkt = pktb_alloc(AF_INET, payload, len, 0);
        
        ip = nfq_ip_get_hdr(pkt);
        nfq_ip_set_transport_header(pkt, ip);
        tcp = nfq_tcp_get_hdr(pkt);

        if (!tcp)
        {
                perror("netinject:non tcp in tcp flow");
                pktb_free(pkt);
                return -1;
        }
        printf("in tcp callback\n");

        if (tcp->syn && IS_ECN(ctx->flags))
        {
                /* cwr,ece */ 
                tcp->cwr = 1;
                tcp->ece = 1;
                
        }
        else if(IS_ECN(ctx->flags)) {
                ip->tos = ctx->flags;
        }

        ip->tos = ctx->flags;
        nfq_ip_set_checksum(ip);
        nfq_tcp_compute_checksum_ipv4(tcp, ip);

        memcpy(payload, pktb_data(pkt), len);
        pktb_free(pkt);

        printf("packet modification done");
        return 0;
}
