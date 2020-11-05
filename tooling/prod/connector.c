#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>

#define HALF_S \
        (struct timespec) { 1, 500000000 }
#define MAX_TTL 50
#define MAX_NTP 60

#define A 1 /* A records */

static int contruct_ip4_sock(char *host, int locport, int extport, int socktype);
static int contruct_ip6_sock(char *host, int locport);
static int check_raw_response(int fd, int ttlfd, char *host);

static void dns_name_fmt(char *dst, char *src);
static char *dns_fmt_name(unsigned char *reader, unsigned char *buffer, int *count);
char *dns_read_name(char *, char *, int *);

struct dns_hdr
{
        uint16_t id;

        uint8_t rd : 1;
        uint8_t tc : 1;
        uint8_t aa : 1;
        uint8_t opcode : 4;
        uint8_t qr : 1;

        uint8_t rcode : 1;
        uint8_t cd : 1;
        uint8_t ad : 1;
        uint8_t z : 1;
        uint8_t ra : 1;

        uint16_t q_count;
        uint16_t ans_count;
        uint16_t auth_count;
        uint16_t add_count;
};

struct dns_q
{
        unsigned short qtype;
        unsigned short qclass;
};

struct dns_rec_data
{
        unsigned short type;
        unsigned short class;
        unsigned int ttl;
        unsigned short len;
};

struct dns_res_record
{
        char *name;
        struct dns_rec_data *resource;
        char *rdata;
};

struct dns_query
{
        char *name;
        struct dns_q *ques;
};

int send_udp_dns_request(char *resolver, char *host)
{

        struct dns_hdr *req;
        struct dns_q *qinfo;
        uint8_t buff[65536], *qname, *reader;
        memset(buff, 0, sizeof(buff));

        struct sockaddr_in addr;
        int fd;

        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0)
        {
                perror("dns:socket creation");
                return -1;
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(6000);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
                perror("dns:bind error");
                close(fd);
                return -1;
        }

        addr.sin_addr.s_addr = inet_addr(resolver);
        addr.sin_port = htons(53);

        // begin assembling request from buffer
        req = (struct dns_hdr *)buff;
        req->id = 123;
        req->qr = 0;
        req->opcode = 0;
        req->aa = 0;
        req->tc = 0;
        req->rd = 1;
        req->ra = 0;
        req->z = 0;
        req->ad = 0;
        req->cd = 0;
        req->rcode = 0;
        req->q_count = htons(1);
        req->ans_count = 0;
        req->auth_count = 0;
        req->add_count = 0;

        /* fill in question doing name compression */
        qname = buff + sizeof(struct dns_hdr);
        dns_name_fmt(qname, host);
        qinfo = (struct dns_q *)&(buff[sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1)]); //fill it
        qinfo->qtype = htons(A);
        qinfo->qclass = htons(1);

        printf("sending\n");

        size_t len = sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1) + sizeof(struct dns_q);

        if (sendto(fd, buff, len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
                perror("sendto failed");
        }
        printf("Done\n");
        sleep(3);

        memset(buff, 0,sizeof buff);

        socklen_t plen = sizeof(struct sockaddr_in);
        if (recvfrom(fd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &plen) < 0)
        {
                perror("dns:recv_failed");
        }

        printf("Recieved response in buff");
        printf("addcount: %d\nauth count:%d\n", ntohs(req->add_count), ntohs(req->ans_count));

        if (ntohs(req->ans_count))
        {
                printf("Got dns answer stop iter query\n");
                // return 0;
        }

        int stop = 0;
        char *name;
        struct dns_rec_data *data;
        struct dns_res_record response;

        req = (struct dns_hdr *)buff;

        reader = &buff[sizeof(struct dns_hdr) + (strlen((const char *)qname)+1) + sizeof(struct dns_q)];

        // copypasta, needs to be versioned into this code
        for (int i = 0; i < ntohs(req->ans_count); i++)
        {
                response.name = dns_fmt_name(reader, buff, &stop);
                reader = reader + stop;

                response.resource = (struct dns_rec_data *)(reader);
                reader = reader + sizeof(struct dns_rec_data);

                if (ntohs(response.resource->type) == 1) //if its an ipv4 address
                {

                        response.rdata = (unsigned char*)malloc(ntohs(response.resource->len));

                        for (int j = 0; j < ntohs(response.resource->len); j++)
                        {
                                response.rdata[j] = reader[j];
                        }

                        response.rdata[ntohs(response.resource->len)] = '\0';
                        reader = reader + ntohs(response.resource->len);
                }
                else
                {
                        printf("else case\n");
                        response.rdata = dns_fmt_name(reader, buff, &stop);
                        reader = reader + stop;
                }

                long *p;
            p=(long*)response.rdata;
            addr.sin_addr.s_addr=(*p); //working without ntohl
            printf("has IPv4 address : %s",inet_ntoa(addr.sin_addr));
        }

        return 0;
}

/**
 * Iterative dns traceroute
 * discover where if ecn marks are being removed
 */
int send_udp_dns_probe(char *host)
{
        return 0;
}

static void format_ntp_request(uint8_t *payload)
{
        payload[0] = 0x23;
        payload[1] = 0x00;
        payload[2] = 0x06;
        payload[3] = 0x20;

        // some point in time to reference
        uint64_t dummy_payload = 0x35eda5acd5c3ec15;
        memcpy(&payload[40], &dummy_payload, sizeof(dummy_payload));
}

int send_udp_ntp_request(char *host, int locport)
{
        uint8_t request[48];
        format_ntp_request(request);

        uint8_t response[48];
        int fd;
        struct sockaddr_in addr;
        struct timespec rst = HALF_S;

        fd = contruct_ip4_sock(host, locport, 123, SOCK_DGRAM);
        if (fd < 0)
        {
                perror("send_ntp:socket creation");
                return -1;
        }

        // Max number of retries before giving up
        // NTP enforces poll delays, so we should sleep alot
        for (int i = 0; i < MAX_NTP; i++)
        {

                if (send(fd, request, sizeof(request), 0) == -1)
                {
                        perror("Failed ot send");
                        close(fd);
                        return -1;
                }

                nanosleep(&rst, &rst);
                if (recv(fd, response, sizeof(response), 0) == -1)
                {
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

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
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

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        {
                perror("ipv4_sock: reuse port");
                close(fd);
                return -1;
        }

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(locport);
        addr.sin6_addr = in6addr_any;

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
        {
                perror("ipv6_create:bind error");
                close(fd);
                return -1;
        }

        memset(&addr, 0, sizeof(addr));

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(80);
        if (inet_pton(AF_INET6, host, &addr.sin6_addr) != 1)
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

static int send_ind_ntp_probe(int fd, struct sockaddr_in *addr, int locport, int ttl)
{

        struct iphdr *ip;
        struct udphdr *udp;
        uint8_t request[4096], *payload;
        memset(request, 0, sizeof(request));

        ip = (struct iphdr *)request;
        udp = (struct udphdr *)(request + sizeof(struct iphdr));
        payload = (uint8_t *)(request + sizeof(struct udphdr) + sizeof(struct iphdr));
        format_ntp_request(payload);

        ip->ihl = 5;
        ip->version = 4;
        ip->id = htonl(54321);
        ip->ttl = ttl;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr("0.0.0.0");
        ip->daddr = (*addr).sin_addr.s_addr;

        udp->uh_sport = htons(locport);
        udp->uh_dport = htons(123);
        udp->uh_ulen = htons(sizeof(struct udphdr) + 48);
        udp->check = 0;

        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 48;

        if (sendto(fd, request, ip->tot_len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0)
        {
                perror("ntpprobe: failed to send\n");
                return -1;
        }

        return 0;
}

int send_udp_ntp_probe(char *host, int locport)
{

        struct sockaddr_in addr;
        struct timespec rst = HALF_S;

        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int ttlfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        int err = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        err |= fcntl(ttlfd, F_SETFL, fcntl(ttlfd, F_GETFL, 0) | O_NONBLOCK);

        if (err)
        {
                perror("ntp_probe:socket non block set\n");
                close(fd);
                close(ttlfd);
                return -1;
        }

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host);
        addr.sin_port = htons(123);

        /* IP_HDRINCL to tell the kernel that headers are included in the packet */
        int one = 1;
        const int *val = &one;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        {
                printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
                return -1;
        }

        for (int i = 1; i < MAX_TTL; i++)
        {
                for (int j = 0; j < 5; j++)
                {
                        nanosleep(&rst, &rst);
                        send_ind_ntp_probe(fd, &addr, locport, i);
                        int resp = check_raw_response(fd, ttlfd, host);
                        if (resp == 0)
                        {
                                printf("Got some response from host\n");
                                goto exit;
                        }
                        if (resp == 1)
                        {
                                break;
                        }
                }
        }
        printf("Did not get response from host\n");
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
        tcp->ack_seq = (flags & 0x02) ? 1 : 0;
        tcp->doff = 5;
        tcp->syn = flags & 0x01;
        tcp->rst = (flags & 0x02) ? 1 : 0;
        tcp->ack = (flags & 0x02) ? 1 : 0;
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
 * 
 * Should be used with traceroute methods
 * as we also check for icmp responses from intermediate nodes
 * 
 * returns:
 *      0: response was read from intended host
 *      1: received response from intermediate node
 *      -1: Othersise, failed
 */
static int check_raw_response(int fd, int ttlfd, char *host)
{

        struct iphdr *ip;
        struct icmphdr *icmp;
        uint8_t buff[4096];
        struct sockaddr_in addr;
        int i = 0;
        while (i++ < 100)
        {
                if (recvfrom(ttlfd, buff, sizeof(buff), 0, NULL, NULL) > 0)
                {
                        // we have some icmp packet
                        // check to see if its a ttl exceeded
                        ip = (struct iphdr *)buff;
                        icmp = (struct icmphdr *)(buff + sizeof(struct iphdr));

                        if (icmp->code == ICMP_EXC_TTL)
                        {
                                printf("got ttl exceed\n");
                                return 1;
                        }
                }

                // otherwise check that we have a response from the host
                if ((recvfrom(fd, buff, sizeof(buff), 0, NULL, NULL)) < 0)
                {
                        printf("failed to read\n");
                        return -1;
                }

                ip = (struct iphdr *)buff;
                addr.sin_addr.s_addr = ip->saddr;
                if (!strcmp(inet_ntoa(addr.sin_addr), host))
                        return 0;
                printf("was not host was %s\n", inet_ntoa(addr.sin_addr));
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
        int ttlfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (fd < 0 || ttlfd < 0)
        {

                perror("tcp_probe:sock creation");
                close(fd);
                close(ttlfd);
                return -1;
        }

        int err = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        err |= fcntl(ttlfd, F_SETFL, fcntl(ttlfd, F_GETFL, 0) | O_NONBLOCK);

        if (err)
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

        for (int ttl = 1; ttl < MAX_TTL; ttl++)
        {
                for (int i = 0; i < 5; i++)
                {
                        send_ind_tcp_probe(fd, &addr, host, locport, ttl, 0x01);
                        nanosleep(&rst, &rst);
                        if (check_raw_response(fd, ttlfd, host) == 0)
                        {
                                goto loop_break;
                        }
                }
        }

        printf("Did not recieve a response from host\n");

loop_break:
        close(fd); /* rst sent on close fd */
        close(ttlfd);
        sleep(3);
        return 0;
}

static char *dns_fmt_name(unsigned char *reader, unsigned char *buffer, int *count)
{
        unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

static void dns_name_fmt(char *dns, char *host)
{
        int lock = 0, i;
        strcat((char *)host, ".");

        for (i = 0; i < strlen((char *)host); i++)
        {
                if (host[i] == '.')
                {
                        *dns++ = i - lock;
                        for (; lock < i; lock++)
                        {
                                *dns++ = host[lock];
                        }
                        lock++; //or lock=i+1;
                }
        }
        *dns++ = '\0';
}
