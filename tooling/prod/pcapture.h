#ifndef PCAPTURE_H
#define PCAPTURE_H 1


#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>

#include "context.h"

struct pcap_controller_t 
{
    pthread_t thread;

    pthread_mutex_t mtx;
    pthread_cond_t cv; // internal cv for waiting for ctx;
    pthread_cond_t cap_rdy; // Wait until component ready to capture
    pthread_cond_t ctx_rdy; // wait until component ready for another ctx
    bool ctx_rdy_flag, cap_rdy_flag; // respective flags



    bool connection_exit, controller_exit;

    // synchronise work context with program
    // pthread_mutex_t mtx;
    // pthread_cond_t cv;
    
    // // synchronise whether pcap is ready to recieve traffic
    // pthread_cond_t cap_rdy;
    // bool cap_rdy_flag,ctx_rdy;

    // // discern whether the controller or sub routine should terminate
    // bool controller_exit;
    // bool connection_exit;

    struct connection_context_t *ctx;
    pcap_t *handle;
    pcap_dumper_t *dump;
    char *pcap_dev, *alias, *outdir;


};

int pcap_debug();
void pcap_free(struct pcap_controller_t *pc);
void pcap_close_context(struct pcap_controller_t *pc);
void pcap_wait_until_rdy(struct pcap_controller_t *pc);
void pcap_push_context(struct pcap_controller_t *pc, struct connection_context_t *ctx);
struct pcap_controller_t * pcap_init();


#endif
