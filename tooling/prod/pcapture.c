#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>

#include "context.h"
#include "pcapture.h"

static void *pcap_controller(void *arg);
static void pcap_log_conn(struct pcap_controller_t *pc);

void pcap_push_context(struct pcap_controller_t *pc, struct connection_context_t *ctx)
{
        pthread_mutex_lock(&pc->mtx);
        while (pc->ctx)
                pthread_cond_wait(&pc->cv, &pc->mtx);

        pc->ctx = ctx;

        pthread_mutex_unlock(&pc->mtx);
        pthread_cond_signal(&pc->cv);
}

/**
 * Sanity checks for pcap
 */
int pcap_debug()
{
        char *device;
        char ip[13];
        char subnet_mask[13];
        bpf_u_int32 ip_raw;
        bpf_u_int32 subnet_mask_raw;
        int lookup_return_code;
        char error_buffer[PCAP_ERRBUF_SIZE];
        struct in_addr address;

        /* Find a device */
        device = pcap_lookupdev(error_buffer);
        if (device == NULL)
        {
                printf("%s\n", error_buffer);
                return 1;
        }

        /* Get device info */
        lookup_return_code = pcap_lookupnet(
            device,
            &ip_raw,
            &subnet_mask_raw,
            error_buffer);
        if (lookup_return_code == -1)
        {
                printf("%s\n", error_buffer);
                return 1;
        }

        /* Get ip in human readable form */
        address.s_addr = ip_raw;
        strcpy(ip, inet_ntoa(address));
        if (ip == NULL)
        {
                perror("inet_ntoa"); /* print error */
                return 1;
        }

        /* Get subnet mask in human readable form */
        address.s_addr = subnet_mask_raw;
        strcpy(subnet_mask, inet_ntoa(address));
        if (subnet_mask == NULL)
        {
                perror("inet_ntoa");
                return 1;
        }

        printf("Device: %s\n", device);
        printf("IP address: %s\n", ip);
        printf("Subnet mask: %s\n", subnet_mask);

        return 0;
}

struct pcap_controller_t *pcap_init()
{
        pthread_t th;
        struct pcap_controller_t *pc = calloc(sizeof(struct pcap_controller_t), 1);

        pthread_mutex_init(&pc->mtx, NULL);
        pthread_cond_init(&pc->cv, NULL);
        pthread_cond_init(&pc->cap_rdy, NULL);

        // start the controller and wait for the connection information to be recived
        if (pthread_create(&th, NULL, pcap_controller, pc))
        {
                perror("pcap:thread creation");
                return NULL;
        }

        pc->thread = th;

        return pc;
}

void pcap_free(struct pcap_controller_t *pc)
{
        pthread_mutex_lock(&pc->mtx);
        pc->connection_exit = true;
        pc->controller_exit = true;
        pthread_mutex_unlock(&pc->mtx);
        pthread_join(pc->thread, NULL);

        pthread_mutex_destroy(&pc->mtx);
        pthread_cond_destroy(&pc->cap_rdy);
        pthread_cond_destroy(&pc->cv);

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

        pthread_mutex_lock(&pc->mtx);
        bool ret = pc->connection_exit;
        pthread_mutex_unlock(&pc->mtx);
        printf("finish check\n");
        return ret;
}

static void pcap_log_conn(struct pcap_controller_t *pc)
{

        char outfile[32];
        sprintf(outfile, "%s-%d.pcap", pc->ctx->host, pc->ctx->port);
        pcap_dumper_t *pd;
        char dev[] = "wlp3s0";
        char filter_exp[32];
        sprintf(filter_exp, "port %d or dst port %d", pc->ctx->port, pc->ctx->port);
        pcap_t *handle;
        char error_buffer[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;
        bpf_u_int32 subnet_mask, ip;

        if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1)
        {
                printf("Could not get information for device: %s\n", dev);
                ip = 0;
                subnet_mask = 0;
        }
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
        if (handle == NULL)
        {
                printf("Could not open %s - %s\n", dev, error_buffer);
                return;
        }
        if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1)
        {
                printf("Bad filter - %s\n", pcap_geterr(handle));
                return;
        }
        if (pcap_setfilter(handle, &filter) == -1)
        {
                printf("Error setting filter - %s\n", pcap_geterr(handle));
                return;
        }

        // buffer is open -> we are capturing but not using packets
        printf("pcap:capture_ready");
        pthread_mutex_lock(&pc->mtx);
        pc->cap_rdy_flag = true;
        pthread_mutex_unlock(&pc->mtx);
        pthread_cond_signal(&pc->cap_rdy);

        pd = pcap_dump_open(handle, outfile);
        do
        {
                pcap_dispatch(handle, -1, &pcap_dump, (u_char *)pd);
        } while (!get_connection_exit(pc));

        // close dump file handle
        pcap_dump_close(pd);
        // close network interface handle
        pcap_close(handle);

        pthread_mutex_lock(&pc->mtx);
        pc->ctx = NULL;
        pthread_mutex_unlock(&pc->mtx);
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

                // wait until exit or context pushed
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
        }

        return NULL;
}