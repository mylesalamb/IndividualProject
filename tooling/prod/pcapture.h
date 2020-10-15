#ifndef PCAPTURE_H
#define PCAPTURE_H 1

#include <pthread.h>

struct pcap_controller_t 
{
    pthread_t thread;

};

int pcap_debug();
struct pcap_controller_t * pcap_init();
void pcap_log_conn(char *host, int port);


#endif