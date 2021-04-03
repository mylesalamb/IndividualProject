#include <stdint.h>
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
#include <linux/ipv6.h>

#include <linux/tcp.h>
#include <linux/udp.h>

#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <sys/types.h>

#include "context.h"
#include "netinject.h"
#include "log.h"

#define IS_ECN(x) (x & 0x03)
#define IS_TCP_CONTROL(x) (x->syn || x->fin)
#define SHOULD_LOG_SEQ(x) ((x->proto == TCP || x->proto == DNS_TCP || x->proto == NTP_TCP) )

static void *nf_controller(void *arg);
static void nf_handle_conn(struct nf_controller_t *nfc);
static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *msg, struct nfq_data *pkt, void *data);
static int nf_handle_tcp(struct connection_context_t *ctx, uint8_t *payload, size_t len);
static int nf_handle_gen_udp(struct connection_context_t *ctx, uint8_t *payload, size_t len);
static int nf_handle_quic_probe(struct connection_context_t *ctx, uint8_t *payload, size_t len);
static int nf_nop(struct connection_context_t *ctx, uint8_t *payload, size_t len) { return 0; }

static int (*dispatch_table[])(struct connection_context_t *ctx, uint8_t *payload, size_t len) = {
    &nf_handle_tcp,       // TCP
    &nf_handle_gen_udp,   // NTP UDP
    &nf_handle_tcp,       // NTP TCP
    &nf_handle_gen_udp,   // DNS UDP
    &nf_handle_tcp,       // DNS TCP
    &nf_handle_gen_udp,   // QUIC
    &nf_handle_tcp,       // TCP PROBE
    &nf_handle_gen_udp,   // NTP UDP PROBE
    &nf_handle_tcp,       // NTP TCP PROBE
    &nf_handle_gen_udp,   // DNS UDP PROBE
    &nf_handle_tcp,       // DNS TCP PROBE
    &nf_handle_quic_probe // QUIC PROBE
};

struct nf_controller_t *nf_init()
{
        struct nf_controller_t *nfc;

        nfc = malloc(sizeof(struct nf_controller_t));
        if (!nfc)
                return NULL;

        pthread_mutex_init(&nfc->mtx, NULL);
        pthread_cond_init(&nfc->cv, NULL);
        pthread_cond_init(&nfc->cap_rdy, NULL);
        pthread_cond_init(&nfc->ctx_rdy, NULL);

        nfc->ctx = NULL;
        nfc->ctx_rdy_flag = true;
        nfc->connection_exit = false;
        nfc->controller_exit = false;
        nfc->queue = NULL;

        if (!(nfc->nfq_handle = nfq_open()))
        {
                LOG_ERR("nfq_open failed\n");
                return NULL;
        }

        if (!(nfc->queue = nfq_create_queue(nfc->nfq_handle, 0, &packet_callback, &nfc->ctx)))
        {
                LOG_ERR("nfq_create_queue failed\n");
                return NULL;
        }

        if (nfq_set_mode(nfc->queue, NFQNL_COPY_PACKET, 0xffff) < 0)
        {
                LOG_ERR("nfq_set_mode failed\n");
                return NULL;
        }

        nfc->nl_handle = nfq_nfnlh(nfc->nfq_handle);
        nfc->fd = nfnl_fd(nfc->nl_handle);

        // Put the socket in non-blocking mode:
        if (fcntl(nfc->fd, F_SETFL, fcntl(nfc->fd, F_GETFL) | SOCK_NONBLOCK) < 0)
        {
                LOG_ERR("set non block failed\n");
                return NULL;
        }

        if (pthread_create(&nfc->th, NULL, &nf_controller, nfc))
        {
                LOG_ERR("create thread\n");
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

                nf_handle_conn(nfc);

                pthread_mutex_lock(&nfc->mtx);
                nfc->ctx = NULL;
                nfc->ctx_rdy_flag = true;
                nfc->connection_exit = false;
                pthread_mutex_unlock(&nfc->mtx);
                pthread_cond_signal(&nfc->ctx_rdy);
        }

        return NULL;
}

static void nf_handle_conn(struct nf_controller_t *nfc)
{
        int res;
        char buf[4096];

        pthread_mutex_lock(&nfc->mtx);
        nfc->cap_rdy_flag = true;
        nfc->controller_exit = false;
        pthread_mutex_unlock(&nfc->mtx);
        pthread_cond_signal(&nfc->cap_rdy);

        while (!nf_get_connection_exit(nfc))
        {
                while ((res = recv(nfc->fd, buf, sizeof(buf), 0)) && res > 0)
                {
                        nfq_handle_packet(nfc->nfq_handle, buf, res);
                }
        }
}
void nf_close_context(struct nf_controller_t *nfc)
{
        pthread_mutex_lock(&nfc->mtx);
        nfc->connection_exit = true;
        pthread_mutex_unlock(&nfc->mtx);
}

void nf_push_context(struct nf_controller_t *nfc, struct connection_context_t *ctx)
{
        // this is exactly the same as netcap, possibillity to refactor? struct component {synchro, pcap || netfilter}?
        pthread_mutex_lock(&nfc->mtx);
        while (!nfc->ctx_rdy_flag)
                pthread_cond_wait(&nfc->ctx_rdy, &nfc->mtx);
        nfc->ctx = ctx;
        nfc->ctx_rdy_flag = false;
        pthread_mutex_unlock(&nfc->mtx);
        pthread_cond_signal(&nfc->cv);
}

void nf_wait_until_rdy(struct nf_controller_t *nfc)
{
        pthread_mutex_lock(&nfc->mtx);
        while (!nfc->cap_rdy_flag)
                pthread_cond_wait(&nfc->cap_rdy, &nfc->mtx);
        nfc->cap_rdy_flag = false;
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
        pthread_cond_destroy(&nfc->cv);
        pthread_cond_destroy(&nfc->cap_rdy);
        pthread_cond_destroy(&nfc->ctx_rdy);
        nfq_destroy_queue(nfc->queue);
        nfq_close(nfc->nfq_handle);
        free(nfc);
}

static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *msg, struct nfq_data *pkt, void *data)
{
        struct connection_context_t *ctx = *(struct connection_context_t **)data;
        int id = 0, len = 0;
        struct nfqnl_msg_packet_hdr *ph;
        uint8_t *payload;

        
        ph = nfq_get_msg_packet_hdr(pkt);
        if (!ph)
        {
                LOG_ERR("get packet header failed\n");
                return 0;
        }

        id = ntohl(ph->packet_id);
        len = nfq_get_payload(pkt, &payload);

        if (!len)
        {
                LOG_ERR("packet len invalid\n");
                return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
        }

        int ret;

        ret = dispatch_table[ctx->proto](ctx, payload, len);

        if (ret)
        {
                LOG_ERR("Jit modification failed -> release packet\n");
                return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
        }
        return nfq_set_verdict(queue, id, NF_ACCEPT, len, payload);
}

// Use kernel types as opposed to netinet
// prevent type collisions and better struct naming
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"

/**
* Prepare packets for mods, and do in an agnostic way
*/
static int gen_ip_handler(struct pkt_buff *pkt, struct connection_context_t *ctx)
{

        struct iphdr *ip4;
        struct ipv6hdr *ip6;

        if (!pkt)
                return -1;

        ip4 = nfq_ip_get_hdr(pkt);

        if (ip4)
        {
                nfq_ip_set_transport_header(pkt, ip4);
                return 0;
        }

        ip6 = nfq_ip6_get_hdr(pkt);

        if (ip6)
        {
                nfq_ip6_set_transport_header(pkt, ip6, ip6->nexthdr);
                return 0;
        }

        return 1;
}

static int gen_ip_udp_checksum(struct connection_context_t *ctx, struct pkt_buff *pkt, struct udphdr *hdr)
{
        struct iphdr *ip4;
        struct ipv6hdr *ip6;

        if (!pkt)
                return -1;

        ip4 = nfq_ip_get_hdr(pkt);

        if (ip4)
        {
                ip4->tos = ctx->flags;
                nfq_ip_set_checksum(ip4);
                nfq_udp_compute_checksum_ipv4(hdr, ip4);
                return 0;
        }

        ip6 = nfq_ip6_get_hdr(pkt);

        if (ip6)
        {
                ip6->priority = ctx->flags >> 4;
                ip6->flow_lbl[0] = ctx->flags << 4;
                nfq_udp_compute_checksum_ipv6(hdr, ip6);
                return 0;
        }

        return -1;
}

static int gen_ip_tcp_checksum(struct connection_context_t *ctx, struct pkt_buff *pkt, struct tcphdr *hdr)
{
        struct iphdr *ip4;
        struct ipv6hdr *ip6;
        int return_value = -1;

        bool mark_tos = ( IS_ECN(ctx->flags) &&   ((!hdr->syn && !hdr->fin && !hdr->rst) ||  ctx->additional & TCP_MARK_CONTROL ));
        bool log_seq = hdr->syn && SHOULD_LOG_SEQ(ctx);

        if(!ctx || !pkt || !hdr)
        {
                return return_value;
        }

        if (!pkt)
                return -1;

        if (IS_ECN(ctx->flags) && hdr->syn)
        {
                
                hdr->ece = 1;
                hdr->cwr = 1;
        }
        else
        {
                hdr->ece = 0;
                hdr->cwr = 0;
        }
        

        ip4 = nfq_ip_get_hdr(pkt);

        if (ip4)
        {
                ip4->tos = 0;

                if (mark_tos)
                        ip4->tos = ctx->flags;

                nfq_ip_set_checksum(ip4);
                nfq_tcp_compute_checksum_ipv4(hdr, ip4);
                return_value = 0;
        }

        ip6 = nfq_ip6_get_hdr(pkt);

        if (ip6)
        {
                if (mark_tos)
                {
                        ip6->priority = ctx->flags >> 4;
                        ip6->flow_lbl[0] = ctx->flags << 4;
                }
                nfq_tcp_compute_checksum_ipv6(hdr, ip6);
                return_value = 0;
        }

        // if we are doing a mid conn tracert
        if(log_seq)
        {
                pthread_mutex_lock(&ctx->tcp_conn.mtx);
                ctx->tcp_conn.tcp_seq = htonl(ntohl(hdr->seq) + 1);
                LOG_INFO("log seq as %ud\n", ntohl(ctx->tcp_conn.tcp_seq));
                pthread_mutex_unlock(&ctx->tcp_conn.mtx);
        }

        return return_value;
}

#pragma GCC diagnostic pop

static int nf_handle_quic_probe(struct connection_context_t *ctx, uint8_t *payload, size_t len)
{
        struct pkt_buff *pkt;
        struct udphdr *udp;
        uint8_t *udp_payload;
        ssize_t payload_len;

        pkt = pktb_alloc(ip_ver_str(ctx->host), payload, len, 0);
        gen_ip_handler(pkt, ctx);
        udp = nfq_udp_get_hdr(pkt);
        if (!udp)
        {
                LOG_ERR("Could not get udp header\n");
                return -1;
        }

        pthread_mutex_lock(&ctx->quic_conn.mtx);
        if (!ctx->quic_conn.pkt_relay)
        {
                
                udp_payload = nfq_udp_get_payload(udp, pkt);
                if (!udp_payload)
                {
                        LOG_ERR("Could not get udp payload\n");
                        return -1;
                }

                payload_len = nfq_udp_get_payload_len(udp, pkt);

                uint8_t *payload_replay = malloc(payload_len);
                if (!payload_replay)
                {
                        LOG_ERR("replay payload malloc failed\n");
                        return -1;
                }
                memcpy(payload_replay, udp_payload, payload_len);
                ctx->quic_conn.pkt_relay = payload_replay;
                ctx->quic_conn.pkt_relay_len = payload_len;
        }
        pthread_mutex_unlock(&ctx->quic_conn.mtx);

        gen_ip_udp_checksum(ctx, pkt, udp);

        memcpy(payload, pktb_data(pkt), len);
        pktb_free(pkt);

        return 0;
}

static int nf_handle_gen_udp(struct connection_context_t *ctx, uint8_t *payload, size_t len)
{
        struct pkt_buff *pkt;
        struct udphdr *udp;

        pkt = pktb_alloc(ip_ver_str(ctx->host), payload, len, 0);

        gen_ip_handler(pkt, ctx);
        udp = nfq_udp_get_hdr(pkt);

        if (!udp)
        {
                perror("netinjection:could not get udp packet");
                pktb_free(pkt);
                return -1;
        }

        gen_ip_udp_checksum(ctx, pkt, udp);

        memcpy(payload, pktb_data(pkt), len);
        pktb_free(pkt);

        return 0;
}

static int nf_handle_tcp(struct connection_context_t *ctx, uint8_t *payload, size_t len)
{

        struct pkt_buff *pkt;
        struct tcphdr *tcp;
        pkt = pktb_alloc(AF_INET, payload, len, 0);

        gen_ip_handler(pkt, ctx);
        tcp = nfq_tcp_get_hdr(pkt);

        if (!tcp)
        {
                perror("netinject:non tcp in tcp flow");
                pktb_free(pkt);
                return -1;
        }

        gen_ip_tcp_checksum(ctx, pkt, tcp);

        memcpy(payload, pktb_data(pkt), len);
        pktb_free(pkt);

        return 0;
}
