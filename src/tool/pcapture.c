#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

// parser incoming packets to inspect for initial ack value
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "pcapture.h"
#include "context.h"
#include "log.h"

static void *pcap_controller(void *arg);
static void pcap_log_conn(struct pcap_controller_t *pc);
static void dump_wrapper(unsigned char *user_arg, const struct pcap_pkthdr *hdr, const unsigned char *bytes);
static struct tcphdr *parse_ipv6_headers(void *hdr, int hdr_type);

void pcap_push_context(struct pcap_controller_t *pc, struct connection_context_t *ctx)
{
        pthread_mutex_lock(&pc->mtx);
        while (!pc->ctx_rdy_flag)
        {
                pthread_cond_wait(&pc->ctx_rdy, &pc->mtx);
        }
        pc->ctx = ctx;
        pc->ctx_rdy_flag = false;
        pthread_mutex_unlock(&pc->mtx);
        pthread_cond_signal(&pc->cv);
}

struct pcap_controller_t *pcap_init(char *alias, char *dirname)
{
        pthread_t th;
        pcap_if_t *devs = NULL;

        /* setup output data directory */
        struct stat st = {0};
        char cwd[PATH_MAX];
        char *outdir = malloc(PATH_MAX + strlen(dirname) + 1);
        if (getcwd(cwd, sizeof(cwd)) == NULL)
        {
                LOG_ERR("cwd\n");
                return NULL;
        }

        sprintf(outdir, "%s/%s", cwd, dirname);
        if (stat(outdir, &st) == -1)
        {
                mkdir(outdir, 0777);
        }

        char errbuff[PCAP_ERRBUF_SIZE];

        pcap_findalldevs(&devs, errbuff);
        if (!devs)
        {
                LOG_ERR("pcap_init:no devices\n");
                return NULL;
        }

        char *dev = malloc(sizeof(char) * strlen(devs->name) + 1);
        if (!dev)
        {
                LOG_ERR("pcap_init:malloc\n");
                return NULL;
        }
        strcpy(dev, devs->name);

        pcap_freealldevs(devs);

        struct pcap_controller_t *pc = calloc(sizeof(struct pcap_controller_t), 1);

        pthread_mutex_init(&pc->mtx, NULL);
        pthread_cond_init(&pc->cv, NULL);
        pthread_cond_init(&pc->cap_rdy, NULL);
        pthread_cond_init(&pc->ctx_rdy, NULL);

        // start the controller and wait for the connection information to be recived
        if (pthread_create(&th, NULL, pcap_controller, pc))
        {
                LOG_ERR("pcap:thread creation\n");
                return NULL;
        }

        pc->thread = th;
        pc->pcap_dev = dev;
        pc->alias = alias;
        pc->outdir = outdir;
        pc->ctx_rdy_flag = true;
        return pc;
}

/**
 * tell component that the connection has ended
 */
void pcap_close_context(struct pcap_controller_t *pc)
{
        pthread_mutex_lock(&pc->mtx);
        pc->connection_exit = true;
        pthread_mutex_unlock(&pc->mtx);
}

void pcap_free(struct pcap_controller_t *pc)
{
        pthread_mutex_lock(&pc->mtx);
        pc->connection_exit = true;
        pc->controller_exit = true;
        pc->ctx = NULL;
        pthread_mutex_unlock(&pc->mtx);
        pthread_cond_signal(&pc->cv);
        pthread_join(pc->thread, NULL);

        pthread_mutex_destroy(&pc->mtx);
        pthread_cond_destroy(&pc->cap_rdy);
        pthread_cond_destroy(&pc->ctx_rdy);
        pthread_cond_destroy(&pc->cv);

        free(pc->pcap_dev);
        free(pc->outdir);
        free(pc);
}
/**
 * Client threads to wait until the pcap controller in ready
 */
void pcap_wait_until_rdy(struct pcap_controller_t *pc)
{
        pthread_mutex_lock(&pc->mtx);
        while (!pc->cap_rdy_flag)
                pthread_cond_wait(&pc->cap_rdy, &pc->mtx);

        pc->cap_rdy_flag = false;
        pthread_mutex_unlock(&pc->mtx);
}

static bool get_connection_exit(struct pcap_controller_t *pc)
{
        bool ret;
        pthread_mutex_lock(&pc->mtx);
        ret = pc->connection_exit;
        pthread_mutex_unlock(&pc->mtx);
        return ret;
}

static void pcap_log_conn(struct pcap_controller_t *pc)
{

        char outfile[256];
        char context_str[128];

        // Setup the name of the file from the controller context
        get_context_str(pc->ctx, context_str);
        sprintf(outfile, "%s/%s", pc->outdir, context_str);
        LOG_INFO("outfile is %s\n", outfile);

        pcap_dumper_t *pd;
        char filter_exp[64];

        sprintf(filter_exp, "port %d or dst port %d or icmp or icmp6", pc->ctx->port, pc->ctx->port);
        LOG_INFO("filter exp is %s\n", filter_exp);
        char error_buffer[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;
        bpf_u_int32 subnet_mask, ip;

        if (pcap_lookupnet(pc->pcap_dev, &ip, &subnet_mask, error_buffer) == -1)
        {
                LOG_ERR("pcap:device lookup\n");
                ip = 0;
                subnet_mask = 0;
        }

        pc->handle = pcap_create(pc->pcap_dev, error_buffer);
        if (!pc->handle)
        {
                LOG_ERR("create handle\n");
                return;
        }
        if (pcap_set_immediate_mode(pc->handle, 1))
        {
                LOG_ERR("Immediate mode\n");
                return;
        }

        if (pcap_activate(pc->handle))
        {
                LOG_ERR("pcap activate\n");
                return;
        }

        if (pcap_compile(pc->handle, &filter, filter_exp, 0, ip) == -1)
        {
                LOG_ERR("compile filter\n");
                return;
        }
        if (pcap_setfilter(pc->handle, &filter) == -1)
        {
                LOG_ERR("set filter\n");
                return;
        }

        if (pcap_setnonblock(pc->handle, 1, error_buffer) == -1)
        {
                LOG_ERR("set non block\n");
                return;
        }

        // buffer is open -> we are capturing but not using packets

        pd = pcap_dump_open(pc->handle, outfile);

        // ready to capture

        pthread_mutex_lock(&pc->mtx);
        pc->cap_rdy_flag = true;
        pc->connection_exit = false;
        pthread_mutex_unlock(&pc->mtx);
        pthread_cond_signal(&pc->cap_rdy);

        LOG_INFO("start packet capture\n");

        if (pd == NULL)
        {
                LOG_ERR("Packet dump failed to open, likely file/folder perm error\n");
        }

        pc->dump = pd;

        do
        {
                pcap_dispatch(pc->handle, -1, &dump_wrapper, (u_char *)pc);
        } while (!get_connection_exit(pc));
        // close dump file handle
        pcap_dump_close(pd);
        pcap_freecode(&filter);
        // close network interface handle
        pcap_close(pc->handle);
}

/**
 * Thread entrypoint for handling
 * pcap connections
 */
static void *pcap_controller(void *arg)
{
        // capture state from init function -> wait until
        struct pcap_controller_t *pc = (struct pcap_controller_t *)arg;

        while (1)
        {
                pthread_mutex_lock(&pc->mtx);
                while (!pc->controller_exit && !pc->ctx)
                        pthread_cond_wait(&pc->cv, &pc->mtx);

                if (pc->controller_exit)
                {
                        pthread_mutex_unlock(&pc->mtx);
                        break;
                }

                pthread_mutex_unlock(&pc->mtx);

                pcap_log_conn(pc);

                pthread_mutex_lock(&pc->mtx);
                pc->ctx = NULL;
                pc->ctx_rdy_flag = true;
                pc->connection_exit = false;
                pthread_mutex_unlock(&pc->mtx);
                pthread_cond_signal(&pc->ctx_rdy);
        }

        return NULL;
}

/* wrapper around pcap dump, so we can capture tcp acks to probe the network path for tcp segements */
static void dump_wrapper(unsigned char *args, const struct pcap_pkthdr *hdr, const unsigned char *pd)
{
        struct pcap_controller_t *pc = (struct pcap_controller_t *)args;

        pthread_mutex_lock(&pc->ctx->tcp_conn.mtx);
        // should we try to capture the ack from the connection setup
        if (hdr && (pc->ctx->proto == TCP || pc->ctx->proto == DNS_TCP || pc->ctx->proto == NTP_TCP) && pc->ctx->additional & TCP_PROBE_PATH // pc->ctx->additional & TCP_PROBE_PATH
        )
        {
                
                
                struct ether_header *ether;
                struct iphdr *iphdr;
                struct ip6_hdr *ip6hdr;
                struct tcphdr *tcphdr;

                //we know this is ethernet, but check network protocol, and calculate offset to tcp header
                ether = (struct ether_header *)pd;
                switch (ntohs(ether->ether_type))
                {
                case ETHERTYPE_IP:
                        iphdr = (struct iphdr *)(ether + 1);
                        if (iphdr->protocol != IPPROTO_TCP)
                                goto abrt;

                        tcphdr = (struct tcphdr *)(iphdr + 1);
                        
                        if (tcphdr->syn && tcphdr->ack)
                        {
                                pc->ctx->tcp_conn.tcp_ack = htonl(ntohl(tcphdr->seq) + 1);
                        }

                        break;
                case ETHERTYPE_IPV6:
                        ip6hdr = (struct ip6_hdr *)(ether + 1);
                        tcphdr = (struct tcphdr *)parse_ipv6_headers(ip6hdr, IPPROTO_IPV6);
                        if(tcphdr && (tcphdr->syn && tcphdr->ack))
                        {
                                pc->ctx->tcp_conn.tcp_ack = htonl(ntohl(tcphdr->seq) + 1);
                        }
                        break;
                default:
                        LOG_INFO("Not ip or ipv6\n");
                        goto abrt;
                }
        }

abrt:
        pthread_mutex_unlock(&pc->ctx->tcp_conn.mtx);
        pthread_cond_signal(&pc->ctx->tcp_conn.cv);

        pcap_dump((u_char *)pc->dump, hdr, pd);
}

static struct tcphdr *parse_ipv6_headers(void *hdr, int hdr_type)
{
        struct ip6_hdr *ip6hdr;
        uint8_t *byte_offset;
        struct ip6_ext *ext;

        switch (hdr_type)
        {
        case IPPROTO_TCP:
                return (struct tcphdr *)hdr;
                break;
        case IPPROTO_IPV6:
                ip6hdr = hdr;
                return parse_ipv6_headers(ip6hdr + 1, ip6hdr->ip6_nxt);
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH:
        case 139:
        case 140:
                byte_offset = (uint8_t *)hdr;
                ext = (struct ip6_ext *)hdr;
                return parse_ipv6_headers(byte_offset + ext->ip6e_len, ext->ip6e_nxt);
        case IPPROTO_NONE:
        default:
                return NULL;
        }
}
