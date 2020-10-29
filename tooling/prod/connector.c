#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>

#define HALF_S \
        (struct timespec) { 1, 500000000 }
#define MAX_TTL 50
#define MAX_NTP 5

static int contruct_ip4_sock(char *host, int locport, int extport, int socktype);
static int contruct_ip6_sock(char *host, int locport);


static int check_tcp_response(int fd, int ttlfd, char *host);

int send_udp_ntp_request(char *host, int locport)
{
        uint8_t request[] = {
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
        };
        // bare min to get a response
        *request = 0x1b; 
        uint8_t response[48];
        int fd;
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        struct timespec rst = HALF_S;

        fd = contruct_ip4_sock(host, locport, 123, SOCK_DGRAM);
        if(fd < 0)
        {
                perror("send_ntp:socket creation");
                return -1;
        }

        // TODO set non block for lost datagrams, and handle in for
        for(int i = 0; i < MAX_NTP; i++)
        {
                printf("loop\n");
                if(send(fd, request, sizeof(request), 0) == -1){
                        perror("Failed ot send");
                        close(fd);
                        return -1;
                }
                
                nanosleep(&rst, &rst);
                if(recv(fd, response, sizeof(response), 0) == -1){
                        perror("Failed to recieve response");
                        close(fd);
                        continue;
                }

                break;
        }

        printf("Got some response\n");
        return 0;

}


/**
 * Send a tcp http request over tcp
 * ipv6 or ipv4 aware
 */
int send_tcp_http_request(char *request, char *host, int locport)
{
        int fd;

        //ipv6 or ipv4
        if (strlen(host) == INET6_ADDRSTRLEN)
        {
                fd = contruct_ip6_sock(host, locport);
        }
        else
        {
                fd = contruct_ip4_sock(host, locport, 80, SOCK_STREAM);
        }
        if (fd < 0)
        {
                perror("tcp-http socket");
                goto fail;
        }

        // set outbound connection

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

static int contruct_ip4_sock(char *host, int locport, int extport, int socktype)
{
        int fd;
        int opt = 1;
        struct sockaddr_in addr;

        fd = socket(AF_INET, socktype, 0);
        if (fd < 0)
        {
                perror("ipv4_socket:create");
                return fd;
        }

        if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        {
                perror("ipv4_sock: reuse port");
                close(fd);
                return -1;
        }

        // bind to local known port
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(locport);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        {
                perror("error binding\n");
                close(fd);
                return -1;
        }

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host);
        addr.sin_port = htons(extport);

         if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
                perror("error connecting to server\n");
                close(fd);
                return -1;
        }



        return fd;
}
static int contruct_ip6_sock(char *host, int locport)
{
        int fd;
        int opt = 1;
        struct sockaddr_in6 addr;
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0)
        {
                perror("ipv6_socket:create");
                return fd;
        }

        if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        {
                perror("ipv4_sock: reuse port");
                close(fd);
                return -1;
        }

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(locport);
        addr.sin6_addr = in6addr_any;

        if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
        {
                perror("ipv6_create:bind error");
                close(fd);
                return -1;
        }

        memset(&addr, 0,sizeof(addr));

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(80);
        if(inet_pton(AF_INET6, host, &addr.sin6_addr) != 1)
        {
                perror("Could not convert addr\n");
                close(fd);
                return -1;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
                perror("error connecting to server\n");
                close(fd);
                return -1;
        }

        return fd;
}

static int check_ntp_probe_response(int fd, int ttlfd, char *host, int locport)
{
        // struct iphdr *ip;
        // struct udphdr *udp;
        // uint8_t buff[4096];

        // while(i++ < 100){
        //         if(recvfrom(ttlfd, buff, sizeof(buff)))
        //                 ;
        // }

        return 0;




}

static int send_ind_ntp_probe(int fd, struct sockaddr_in *addr, int locport, int ttl)
{
        struct iphdr *ip;
        struct udphdr *udp;
        uint8_t request[4096], *payload;

        ip = (struct iphdr*) request;
        udp = (struct udphdr*) (request + sizeof(struct iphdr));
        payload = (uint8_t *)(udp + sizeof(struct udphdr));
        *payload = 0x1b;

        ip->ihl = 5;
        ip->version = 4;
        ip->id = htons(54321);
        ip->ttl = ttl;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr("0.0.0.0");
        ip->daddr = (*addr).sin_addr.s_addr;

        udp->source = htons(locport);
        udp->dest = htons(123);
        udp->len = 48;
        
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + udp->len;

        if(send(fd, request, ip->tot_len, 0) == -1){
                perror("ntpprobe: failed to send\n");
                return -1;
        }

        return 0;
}

int send_udp_ntp_probe(char* host, int locport)
{

        struct sockaddr_in addr;
        struct timespec rst = HALF_S;
        
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int ttlfd  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        int err = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        err |= fcntl(ttlfd, F_SETFL, fcntl(ttlfd, F_GETFL, 0) | O_NONBLOCK);

        if(err)
        {
                perror("ntp_probe:socket non block set\n");
                close(fd);
                close(ttlfd);
                return -1;
        }


        addr.sin_family = AF_INET;
        addr.sin_port = htons(locport);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        {
                perror("error binding\n");
                close(fd);
                return -1;
        }

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host);
        addr.sin_port = htons(123);

         if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
                perror("error connecting to server\n");
                close(fd);
                return -1;
        }

        /* IP_HDRINCL to tell the kernel that headers are included in the packet */
        int one = 1;
        const int *val = &one;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        {
                printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
                return -1;
        }


        for(int i = 1; i < MAX_TTL; i++){
                for(int j = 0; j < 5; j++){
                        nanosleep(&rst, &rst);
                        send_ind_ntp_probe(fd, &addr, locport, i);
                        if(check_tcp_response(fd, ttlfd, host)==0)
                        goto exit;
                }
        }
exit:


        return 0;
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
        ip->saddr = inet_addr("0.0.0.0");
        ip->daddr = (*addr).sin_addr.s_addr;

        tcp->source = htons(locport);
        tcp->dest = htons(80);
        tcp->seq = 123123;
        tcp->ack_seq = (flags & 0x02) ? 1:0;
        tcp->doff = 5;
        tcp->syn = flags & 0x01;
        tcp->rst = (flags & 0x02) ? 1:0;
        tcp->ack = (flags & 0x02) ? 1:0;
        tcp->window = htons(1000);

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
 * 
 * returns:
 *      0: response was read from intended host
 *      1: received response from intermediate node
 *      -1: Othersise, failed
 */
static int check_tcp_response(int fd, int ttlfd, char *host)
{

        struct iphdr *ip;
        struct icmphdr *icmp;
        uint8_t buff[4096];
        struct sockaddr_in addr;
        int i = 0;
        while (i++ < 100)
        {
                if(recvfrom(ttlfd, buff, sizeof(buff), 0, NULL, NULL) > 0)
                {
                        // we have some icmp packet
                        // check to see if its a ttl exceeded
                        ip = (struct iphdr *)buff;
                        icmp = (struct icmphdr *)(buff + sizeof(struct iphdr));

                        if(icmp->code == ICMP_EXC_TTL){
                                return -1;
                        }
                }
                
                // otherwise check that we have a response from the host
                if ((recvfrom(fd, buff, sizeof(buff), 0, NULL, NULL)) < 0)
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

        /* two sockets one for reading ICMP one for reading TCP */
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        int ttlfd  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (fd < 0 || ttlfd < 0)
        {
                
                perror("tcp_probe:sock creation");
                close(fd);
                close(ttlfd);
                return -1;
        }

        int err = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        err |= fcntl(ttlfd, F_SETFL, fcntl(ttlfd, F_GETFL, 0) | O_NONBLOCK);

        if(err)
        {
                perror("tcp_probe:socket non block set\n");
                close(fd);
                close(ttlfd);
                return -1;
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(locport);
        addr.sin_addr.s_addr = inet_addr(host);

        /* IP_HDRINCL to tell the kernel that headers are included in the packet */
        int one = 1;
        const int *val = &one;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        {
                printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
                return -1;
        }

        int reset = 0;

        for (int ttl = 1; ttl < MAX_TTL; ttl++)
        {
                for (int i = 0; i < 5; i++)
                {
                        send_ind_tcp_probe(fd, &addr, host, locport, ttl, 0x01);
                        nanosleep(&rst, &rst);       
                        if (check_tcp_response(fd, ttlfd, host) == 0)
                        {
                                goto loop_break;
                        }
                }
        }

loop_break:
        close(fd); /* rst sent on close fd */
        close(ttlfd); 
        sleep(3);
        return 0;
}