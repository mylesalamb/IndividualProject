#include "connector.h"
#include "pcapture.h"

int main(int argc, char **argv)
{
        pcap_debug();
        pcap_log_conn("93.93.131.127", 6000);
        send_tcp_http_request(
            "GET /teaching/index.html HTTP/1.1\r\nHost: www.csperkins.org\r\nConnection: close\r\n\r\n",
            "93.93.131.127",
            6000);

        return 0;

    
}