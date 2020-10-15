#include <stdio.h>
#include "connector.h"
#include "pcapture.h"
#include "context.h"


int main(int argc, char **argv)
{
        // pcap_debug();
        // pcap_log_conn("93.93.131.127", 6000);


        char *host = "93.93.131.127";

        struct connection_context_t context = {
                host, 1,6000,0
        };

        
        struct pcap_controller_t *pc = pcap_init();

        pcap_push_context(pc, &context);
        pcap_wait_until_rdy(pc);
        send_tcp_http_request(
            "GET /teaching/index.html HTTP/1.1\r\nHost: www.csperkins.org\r\nConnection: close\r\n\r\n",
            "93.93.131.127",
            6000);
        pcap_free(pc);



        return 0;

    
}