#ifndef PCAPTURE_H
#define PCAPTURE_H 1

#include <pthread.h>
#include <stdbool.h>

#include "context.h"

struct pcap_controller_t 
{
    pthread_t thread;
    // synchronise with the other parts of the program
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    
    pthread_cond_t cap_rdy;
    bool cap_rdy_flag;

    // discern whether the controller or sub routine should terminate
    bool controller_exit;
    bool connection_exit;

    struct connection_context_t *ctx;


};

int pcap_debug();
struct pcap_controller_t * pcap_init();


#endif