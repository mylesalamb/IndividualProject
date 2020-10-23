#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>

#define HALF_S \
        (struct timespec) { 0, 500000000 }
#define MAX_TTL 50

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

        char buff[1024];
        ssize_t request_len = strlen(request);

        if (write(fd, request, request_len) >= 0)
        {
                while (read(fd, buff, sizeof(buff)) > 0)
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

/**
 * Send an individual tcp segement
 * flags denotes whether a syn or fin segment should be sent
 */
static int send_ind_tcp_probe(int fd, struct sockaddr_in *addr, char *host, int locport, int ttl, uint8_t flags)
{
        struct iphdr *ip;
        struct tcphdr *tcp;
        uint8_t buff[4096];

        memset(buff, 0, sizeof(buff));

        ip = (struct iphdr *)buff;
        tcp = (struct tcphdr *)(buff + sizeof(struct iphdr));

        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        ip->id = htons(54321);
        ip->ttl = ttl;
        ip->protocol = IPPROTO_TCP;
        ip->check = 0;
        ip->saddr = inet_addr("0.0.0.0");
        ip->daddr = (*addr).sin_addr.s_addr;

        tcp->source = htons(locport);
        tcp->dest = htons(80);
        tcp->seq = 123123;
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->fin = flags & 0x02;
        tcp->syn = flags & 0x01;
        tcp->rst = 0;
        tcp->psh = 0;
        tcp->ack = 0;
        tcp->urg = 0;
        tcp->window = htons(1000);
        tcp->check = 0;
        tcp->urg_ptr = 0;

        if (sendto(fd, buff, ip->tot_len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0)
        {
                perror("tcp_probe:send\n");
                fprintf(stderr, "send returned: %s\n", strerror(errno));
                return -1;
        }

        return 0;
}

/**
 * check from the socket if we get a response from the host
 * this is really crude
 */
static int check_tcp_response(int fd, char *host)
{

        struct iphdr *ip;
        uint8_t buff[65536];
        struct sockaddr_in addr;
        int i = 0;
        while(i++ < 100){
        if ((recvfrom(fd, buff, sizeof(buff), 0, NULL, NULL)) == -1)
                return -1;
        

        ip = (struct iphdr *)buff;
        addr.sin_addr.s_addr = ip->saddr;
        if (!strcmp(inet_ntoa(addr.sin_addr), host))
                return 0;
        
        }
        return -1;
}

/**
 * Simple traceroute implementation for sniffing when packets are lost on the network
 * 
 * We use a raw socket syn over icmp as it will get round some simple firewalls
 * Note that we do not set ECN or calc checksum, connector.c is responsible for sending
 * requests, and is agnostic of application context, see netinject.c for context aware modifications
 */
int send_tcp_syn_probe(char *host, int locport)
{

        struct sockaddr_in addr;
        struct timespec rst = HALF_S;
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (fd < 0)
        {
                perror("tcp_probe:sock creation");
                return -1;
        }

        int status = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

        addr.sin_family = AF_INET;
        addr.sin_port = htons(locport);
        addr.sin_addr.s_addr = inet_addr(host);

        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        {
                printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
                return -1;
        }

        for (int ttl = 1; ttl < MAX_TTL; ttl++)
        {
                for (int i = 0; i < 2; i++)
                {
                        send_ind_tcp_probe(fd, &addr, host, locport, ttl, 0x01);
                        nanosleep(&rst, &rst);
                        // read to see if we get an ack
                        // send a fin if we do, everything gets a bit confused if we dont
                        if (check_tcp_response(fd, host) == 0)
                        {
                                printf("seen response :)\n");
                                send_ind_tcp_probe(fd, &addr, host, locport, MAX_TTL, 0x02);
                                goto loop_break;
                        }
                }
        }
loop_break:
        sleep(3);
        return 0;
}