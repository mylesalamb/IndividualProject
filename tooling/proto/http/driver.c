#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#define ECT0 0x02
#define ECT1 0x01

enum ECN_OPTS {
        ECN_OUT_IN = 1,
        ECN_IN = 2,
        ECN_OFF = 0,
};

static int socket_factory(int domain, int type, int dscp);
static int set_ecn(int ecn_opt);

int main(int argc, char **argv)
{

        int fd;
        struct sockaddr_in addr;
        char *server_addr = "93.93.131.127";

        fd = socket_factory(AF_INET, SOCK_STREAM, ECT0);
        // if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        // {
        //         printf("error binding\n");
        // }

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(server_addr);
        addr.sin_port = htons(80);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
                printf("error connecting to server\n");
        }

        // Send request
        char *request = "GET /teaching/index.html HTTP/1.1\r\nHost: www.csperkins.org\r\nConnection: close\r\n\r\n";
        ssize_t request_len = strlen(request);

        if (send(fd, request, request_len, 0) != request_len)
        {
                //no op
        }

        close(fd);

        return EXIT_SUCCESS;
}

static int socket_factory(int domain, int type, int tos)
{
        int fd;

        fd = socket(domain, type, 0);
        if (fd == -1)
        {
                printf("Socket creation failed, returned: %s\n", strerror(errno));
        }
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(6001);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        {
                printf("error binding\n");
        }

        if(tos && setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0){
                printf("Failed to set ECN\n");
        }

        set_ecn(ECN_OFF);
        
        int reuse = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)))
        {
        }

        return fd;
}

// Hack to enable / Disable ecn between connections
// removes any notion of parallelism for this solution
// alternatively we can do a raw sockets implementation
// Allows greater control over dscp, ECT0 or ECT1
// This is likely only an issue with TCP due to the
// tethering with the cc algorithm
static int set_ecn(int ecn_opt)
{
        FILE * handle = fopen("/proc/sys/net/ipv4/tcp_ecn","w");
        if(handle == NULL)
        {
                printf("Open file failed, returned: %s", strerror(errno));
        }
        fprintf(handle, "%d\n", ecn_opt);
        fclose(handle);
        return 0;
}