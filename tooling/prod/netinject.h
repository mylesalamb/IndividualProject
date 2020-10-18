#ifndef NETINJECT_H
#define NETINJECT_H 1

#include <pthread.h>
#include <stdbool.h>

#include <stdint.h> // lib net filter has an undocumented dependency on stdint?
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "context.h"


struct nf_controller_t
{
        pthread_t th;
        struct connection_context_t *ctx;

        pthread_mutex_t mtx;
        pthread_cond_t rdy; // signify ready state
        pthread_cond_t cv; // signify having work context

        
        bool rdy_flag;
        bool connection_exit;
        bool controller_exit;

        // handle state
        int fd;
        struct nfq_handle *nfq_handle;
        struct nfq_q_handle *queue;
        struct nfnl_handle *nl_handle;

};

struct nf_controller_t *nf_init();
void nf_push_context(struct nf_controller_t *nfc, struct connection_context_t *ctx);
void nf_wait_until_rdy(struct nf_controller_t *nfc);
void nf_free(struct nf_controller_t *nfc);
void nf_close_context(struct nf_controller_t *nfc);


#endif