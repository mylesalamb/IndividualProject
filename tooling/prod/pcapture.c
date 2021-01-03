#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#include "pcapture.h"
#include "context.h"
#include "log.h"

static void *pcap_controller(void *arg);
static void pcap_log_conn(struct pcap_controller_t *pc);
static void dump_wrapper(unsigned char *user_arg, const struct pcap_pkthdr *hdr, const unsigned char *bytes);

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
                LOG_ERR("dump open\n");
        }

        do
        {

                pcap_dispatch(pc->handle, -1, &pcap_dump, (u_char *)pd);
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

static void dump_wrapper(unsigned char *user_arg, const struct pcap_pkthdr *hdr, const unsigned char *bytes)
{

        if (hdr)
                LOG_INFO("Packet capped, nop\n");

        pcap_dump(user_arg, hdr, bytes);
}