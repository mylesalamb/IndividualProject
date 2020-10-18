#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

int send_tcp_http_request(char *request, char *host, int locport)
{
        int fd;
        struct sockaddr_in addr;
        int addr_type;

        //ipv6 or ipv4
        if (strlen(host) == INET6_ADDRSTRLEN)
        {
                addr_type = AF_INET6;
        }
        else
        {
                addr_type = AF_INET;
        }

        fd = socket(addr_type, SOCK_STREAM, 0);
        if (fd < 0)
        {
                perror("tcp-http socket");
                goto fail;
        }

        // bind to local known port
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_family = addr_type;
        addr.sin_port = htons(locport);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        {
                perror("error binding\n");
                goto fail;
        }

        // set outbound connection

        addr.sin_family = addr_type;
        addr.sin_addr.s_addr = inet_addr(host);
        addr.sin_port = htons(80);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
                perror("error connecting to server\n");
                goto fail;
        }

        ssize_t request_len = strlen(request);

        if (write(fd, request, request_len) >= 0)
        {
                while (read(fd, NULL, 10000) > 0)
                {
                        
                }
        }

        
        sleep(3);
        close(fd);
        
        
        return 0;
fail:
        close(fd);
        return -1;
}