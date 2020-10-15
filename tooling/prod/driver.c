#include <stdio.h>
#include "connector.h"
#include "pcapture.h"
#include "context.h"


int main(int argc, char **argv)
{
        // pcap_debug();
        // pcap_log_conn("93.93.131.127", 6000);


        char *host = "hello-host";

        struct connection_context_t context = {
                host, 1,6000,0
        };

        printf("pcap:controller_init\n");
        struct pcap_controller_t *pc = pcap_init();

        // push connection context
        pthread_mutex_lock(&pc->mtx);
        pc->ctx = &context;
        pthread_mutex_unlock(&pc->mtx);
        pthread_cond_signal(&pc->cv);



        // wait for packet capturer to become available
        printf("pcap:controller wait for rdy\n");
        pthread_mutex_lock(&pc->mtx);
        while(!pc->cap_rdy_flag)
            pthread_cond_wait(&pc->cap_rdy, &pc->mtx);
        pthread_mutex_unlock(&pc->mtx);

        printf("connector:send tcp\n");
        send_tcp_http_request(
            "GET /teaching/index.html HTTP/1.1\r\nHost: www.csperkins.org\r\nConnection: close\r\n\r\n",
            "93.93.131.127",
            6000);

        printf("main:set_exit\n");
        pthread_mutex_lock(&pc->mtx);
        pc->connection_exit = true;
        pc->controller_exit = true;
        pthread_mutex_unlock(&pc->mtx);

        printf("main: waiting for thread\n");
        pthread_join(pc->thread, NULL);



        return 0;

    
}