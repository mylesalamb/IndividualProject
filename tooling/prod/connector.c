#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>
//#include <arpa/nameser.h>

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>

#define HALF_S \
        (struct timespec) { 5, 000000000 }
#define RAW_DELAY \
        (struct timespec) { 1, 500000000 }
#define MAX_TTL 50
#define MAX_NTP 60
#define MAX_UDP 5
#define MAX_RAW 100

/* DNS FLAGS -> support for minimal iterative dns lookups */
#define AAAA 28
#define A 1
#define RECURSE 1
#define ITER 0

#define PORT_NTP 123
#define PORT_DNS 53
#define PORT_HTTP 80

/* Basic socket abstractions that make things a little easier */

static int construct_ip4_sock(char *host, int locport, int extport, int socktype);
static int construct_ip6_sock(char *host, int locport, int extport, int socktype);
static int get_ipstr_type(char *host);

static int check_raw_response(int fd, int ttlfd, char *host);
static uint8_t *format_raw_iphdr(char *host, uint8_t *buffer, ssize_t payload_len, int proto, int ttl);
static int tcp_send_all(int fd, uint8_t *buff, size_t len);
static int tcp_dns_recv_all(int fd, uint8_t *buff, size_t len);

static int udp_retry_send(int fd, uint8_t *payload, size_t payload_len, uint8_t *response, size_t response_len);

/* Try more than once to send a udp request until we get some response */
static int udp_retry_send(int fd, uint8_t *payload, size_t payload_len, uint8_t *response, size_t response_len)
{
        if (fd < 0 || !payload)
                return -1;

        int ret_code = 0;

        // sleep between sends
        struct timespec rst = HALF_S;

        for (int i = 0; i < MAX_UDP; i++)
        {

                if (send(fd, payload, payload_len, 0) < 0)
                {
                        perror("udp_retry_send:send");
                        return -1;
                }
                nanosleep(&rst, &rst);

                if (recv(fd, response, response_len, 0) > 0)
                {
                        ret_code = 1;
                        break;
                }
        }

        return ret_code;
}

static uint8_t *format_raw_iphdr(
    char *host,
    uint8_t *buffer,
    ssize_t payload_len,
    int proto,
    int ttl)
{
        struct iphdr *ip4 = (struct iphdr *)buffer;
        struct ip6_hdr *ip6 = (struct ip6_hdr *)buffer;

        if (!host || !buffer)
                return NULL;

        int hdr_type = get_ipstr_type(host);

        if (hdr_type == 4)
        {

                inet_pton(AF_INET, host, &(ip4->daddr));
                inet_pton(AF_INET, "0.0.0.0", &(ip4->saddr));

                ip4->ihl = 5;
                ip4->version = 4;
                ip4->tot_len = sizeof(struct iphdr) + payload_len;
                ip4->id = htons(54321);
                ip4->ttl = ttl;
                ip4->protocol = proto;

                return buffer + sizeof(struct iphdr);
        }
        else if (hdr_type == 6)
        {
                inet_pton(AF_INET6, host, &ip6->ip6_dst);
                inet_pton(AF_INET6, "0:0:0:0:0:0:0:0", &ip6->ip6_src);

                ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = (struct ip6_hdr) + payload_len;
                ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
                ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = proto;
                ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x12345678);
                ip6->ip6_ctlun.ip6_un2_vfc = 6;




                return buffer + sizeof(struct ip6_hdr);
        }
        else
        {
                fprintf(stderr, "format raw: ip version not recognised\n");
                return NULL;
        }
}

/* Assume ipstrs only ever use the 'common' formatting */
static int get_ipstr_type(char *host)
{
        return (strchr(host, '.') ? 4 : 6);
}

static int construct_ip4_sock(char *host, int locport, int extport, int socktype)
{
        int fd;
        int opt = 1;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(struct sockaddr_in));

        fd = socket(AF_INET, socktype, 0);
        if (fd < 0)
        {
                perror("ipv4_sock: create");
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
                perror("ipv4_sock: bind");
                close(fd);
                return -1;
        }

        // add flag opt for udp, makes adapting some to ipv6 much easier
        if (socktype == SOCK_STREAM || 1)
        {

                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = inet_addr(host);
                addr.sin_port = htons(extport);

                if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
                {
                        perror("ipv4_sock: connect");
                        close(fd);
                        return -1;
                }
        }
        if (socktype == SOCK_DGRAM)
        {
                if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
                {
                        perror("ipv4_sock: non block");
                        close(fd);
                        return -1;
                }
        }

        return fd;
}

static int construct_ip6_sock(char *host, int locport, int extport, int socktype)
{

        int fd;
        int opt = 1;
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(struct sockaddr_in6));

        fd = socket(AF_INET6, socktype, 0);
        if (fd < 0)
        {
                perror("ipv6_sock: create");
                return fd;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        {
                perror("ipv6_sock: reuse port");
                close(fd);
                return -1;
        }

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(locport);
        addr.sin6_addr = in6addr_any;

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
        {
                perror("ipv6_sock: bind");
                close(fd);
                return -1;
        }

        memset(&addr, 0, sizeof(addr));

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(extport);
        if (inet_pton(AF_INET6, host, &addr.sin6_addr) != 1)
        {
                perror("ipv6_sock: assign addr");
                close(fd);
                return -1;
        }

        if (socktype == SOCK_STREAM || 1)
        {

                if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
                {
                        perror("ipv6_sock: connect");
                        close(fd);
                        return -1;
                }
        }

        if (socktype == SOCK_DGRAM)
        {
                if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
                {
                        perror("ipv6_sock: non block");
                        close(fd);
                        return -1;
                }
        }

        return fd;
}

/**
 * check from the socket if we get a response from the host
 * 
 * Should be used with traceroute methods
 * as we also check for icmp responses from intermediate nodes
 * 
 * returns:
 *      0 : response was read from intended host
 *      1 : received response from intermediate node
 *     -1 : Othersise, failed
 */
static int check_raw_response(int fd, int ttlfd, char *host)
{

        struct iphdr *ip;
        struct ip6_hdr *ip6;

        struct icmphdr *icmp;
        struct icmp6_hdr *icmp6;

        int ipver = get_ipstr_type(host);

        uint8_t buff[4096];
        uint8_t saddr[16];

        if(ipver == 4){
                inet_pton(AF_INET, host, saddr);
        }
        else if(ipver == 6)
        {
                inet_pton(AF_INET6, host, saddr);
        }
        

        int i = 0;
        while (i++ < MAX_RAW)
        {
                if (recvfrom(ttlfd, buff, sizeof(buff), 0, NULL, NULL) > 0)
                {
                        if (ipver == 4)
                        {
                                ip = (struct iphdr *)buff;
                                icmp = (struct icmphdr *)(buff + sizeof(struct iphdr));

                                if (icmp->code == ICMP_EXC_TTL)
                                {
                                        printf("got ttl exceed\n");
                                        return 1;
                                }
                        }
                        else
                        {
                                ip6 = (struct ip6_hdr *)buff;
                                icmp6 = (struct icmp6_hdr *)(buff + sizeof(struct ip6_hdr));

                                if (icmp6->icmp6_code == ICMP6_TIME_EXCEED_TRANSIT)
                                {
                                        printf("got time exceeded\n");
                                        return 1;
                                }
                                printf("got some icmp *** return!\n");
				return 1;
                        }
                }

                // otherwise check that we have a response from the host
                if ((recvfrom(fd, buff, sizeof(buff), 0, NULL, NULL)) < 0)
                {
                        printf("failed to read\n");
                        return -1;
                }

                if (ipver == 4)
                {
                        // switch this to a byte comparison, dont rely on string formatting of ip addrs
                        ip = (struct iphdr *)buff;
                        
                        if (!memcmp(&ip->saddr, saddr, sizeof(ip->saddr)))
                                return 0;
                        printf("was not host\n");
                }
                else
                {
                        ip6 = (struct ip6_hdr *)buff;

                        if(!memcmp(&ip6->ip6_src, saddr, sizeof(saddr)))
                                return 0;

                        printf("Was not host\n");
                }
                
        }
        return -1;
}

static int tcp_send_all(int fd, uint8_t *buff, size_t len)
{
        if (fd < 0 || len <= 0 || !buff)
                return -1;

        uint8_t *ptr = buff;
        size_t sent = 0;

        while (sent != len)
        {
                int ret = send(fd, ptr, len - sent, 0);
                if (ret < 0)
                        goto fail;
                sent += ret;
                ptr = buff + sent;
        }

        return 0;

fail:
        return 1;
}

static int tcp_dns_recv_all(int fd, uint8_t *buff, size_t buff_len)
{
        uint8_t *ptr = buff;
        uint16_t resp_length;

        int received = recv(fd, buff, buff_len, 0);

        if (received < 0)
                return -1;

        // get and discount length of the response
        ptr += received;
        resp_length = ntohs(*(uint16_t *)buff);
        received -= 2;

        printf("recieved %d, %d to go\n", received, resp_length - received);

        while (received != resp_length)
        {

                int status = recv(fd, ptr, buff_len - received, 0);
                if (status < 0)
                        return -1;

                received += status;
                ptr += status;
        }

        return received;
}

/* HTTP client + tcp traceroute implementation */

/**
 * Send a tcp http request over tcp
 * ipv6 or ipv4 aware
 */
int send_tcp_http_request(char *request, char *host, int locport)
{
        int fd;

        //ipv6 or ipv4
        if (get_ipstr_type(host) == 6)
        {
                fd = construct_ip6_sock(host, locport, PORT_HTTP, SOCK_STREAM);
        }
        else
        {
                fd = construct_ip4_sock(host, locport, PORT_HTTP, SOCK_STREAM);
        }
        if (fd < 0)
        {
                goto fail;
        }

        char buff[1024];
        ssize_t request_len = strlen(request);

        tcp_send_all(fd, (uint8_t *)request, request_len);

        while (recv(fd, buff, sizeof(buff), 0) > 0)
                ;

        close(fd);
        sleep(3);
        printf("returned from send http\n");
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
        ip->saddr = inet_addr("0.0.0.0");
        ip->daddr = (*addr).sin_addr.s_addr;

        tcp->source = htons(locport);
        tcp->dest = htons(PORT_HTTP);
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
 * Simple traceroute implementation for sniffing when packets are lost on the network
 * 
 * We use a raw socket syn over icmp as it will get round some simple firewalls
 * Note that we do not set ECN or calc checksum, connector.c is responsible for sending
 * requests, and is agnostic of application context, see netinject.c for context aware modifications
 */
int send_tcp_syn_probe(char *host, int locport)
{

        struct sockaddr_in addr;
        struct timespec rst = RAW_DELAY;

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

/* NTP client + traceroute implementation */

static void dns_name_fmt(uint8_t *dst, uint8_t *src);
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

#pragma pack(push, 1)
struct dns_rec_data
{
        unsigned short type;
        unsigned short class;
        unsigned int ttl;
        unsigned short len;
};
#pragma pack(pop)

struct dns_res_record
{
        char *name;
        struct dns_rec_data *resource;
        char *rdata;
        struct dns_res_record *nxt;
};

struct dns_query
{
        char *name;
        struct dns_q *ques;
};

struct dns_response
{
        struct dns_res_record *answer, *auth, *additional;
};

/**
 * Get intermediate namerservers normally
 * using resolver in /etc/resolv.conf
 * 
 * This is how dig +trace works
 * so we dont iteratively have to resolve nameservers
 * as well 
 * 
 * As long as we test 'on path' nodes
 */
static void *get_dns_resolver(char *ret)
{
        FILE *handle;
        int len;
        char buff[256], *ptr;

        if ((handle = fopen("/etc/resolv.conf", "r")) == NULL)
        {
                perror("dns:get resolv conf handle");
                return NULL;
        }

        ptr = NULL;

        while (fgets(buff, sizeof(buff), handle))
        {
                if (*buff == '#')
                {
                        continue;
                }

                // the rest of the line is the ip of the namserver
                ptr = strtok(buff, " ");
                ptr = strtok(NULL, " ");

                if (!ptr)
                        continue;

                // remove newline
                len = strlen(ptr) - 1;
                ptr[len] = '\0';

                break;
        }

        if (!ptr)
                return NULL;

        if (!ret)
                return NULL;

        strcpy(ret, ptr);
        fclose(handle);

        return ret;
}

/**
 * Take a buffer and format a suitable dns request
 * returning the length of the request
 */
static int format_dns_request(uint8_t *buff, int record_type, char *host, uint8_t flags)
{
        struct dns_hdr *req;
        struct dns_q *qinfo;
        uint8_t *qname;

        // begin assembling request from buffer
        req = (struct dns_hdr *)buff;
        req->id = 123;
        req->qr = 0;
        req->opcode = 0;
        req->aa = 0;
        req->tc = 0;
        req->rd = (flags & 0x01) ? 1 : 0;
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
        dns_name_fmt(qname, (uint8_t *)host);

        qinfo = (struct dns_q *)&(buff[sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1)]); //fill it
        qinfo->qtype = htons(record_type);
        qinfo->qclass = htons(1);

        return sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1) + sizeof(struct dns_q);
}

static void free_dns_response(struct dns_response response)
{
        struct dns_res_record *ptr;

        ptr = response.additional;
        while (ptr)
        {
                struct dns_res_record *nxt = ptr->nxt;
                free(ptr->name);
                free(ptr->rdata);
                free(ptr);
                ptr = nxt;
        }
        ptr = response.auth;
        while (ptr)
        {
                struct dns_res_record *nxt = ptr->nxt;
                free(ptr->name);
                free(ptr->rdata);
                free(ptr);
                ptr = nxt;
        }
        ptr = response.answer;
        while (ptr)
        {
                struct dns_res_record *nxt = ptr->nxt;
                free(ptr->name);
                free(ptr->rdata);
                free(ptr);
                ptr = nxt;
        }
}

/**
 * Take a response buffer
 * 
 * parse the response and return the answer records
 * 
 * ie)  answers
 *      additional records etc
 */
static struct dns_response parse_dns_response(uint8_t *buff)
{

        struct dns_response ret = {NULL, NULL, NULL};

        uint8_t *reader;
        uint8_t *qname = buff + sizeof(struct dns_hdr);
        int stop = 0;

        struct dns_hdr *req;
        struct dns_res_record *response;

        req = (struct dns_hdr *)buff;
        reader = &buff[sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1) + sizeof(struct dns_q)];

        for (int i = 0; i < ntohs(req->ans_count); i++)
        {
                response = malloc(sizeof(struct dns_res_record));
                if (!response)
                {
                        perror("dns:malloc response");
                        goto fail;
                }

                response->name = dns_fmt_name(reader, buff, &stop);
                reader = reader + stop;

                response->resource = (struct dns_rec_data *)(reader);
                reader = reader + sizeof(struct dns_rec_data);

                if (ntohs(response->resource->type) == A) //if its an ipv4 address
                {

                        response->rdata = (char *)malloc(ntohs(response->resource->len));

                        for (int j = 0; j < ntohs(response->resource->len); j++)
                        {
                                response->rdata[j] = reader[j];
                        }

                        // response->rdata[ntohs(response->resource->len)] = '\0';
                        reader = reader + ntohs(response->resource->len);
                }
                else
                {
                        printf("was not ipv4 was type %d", ntohs(response->resource->type));
                        response->rdata = dns_fmt_name(reader, buff, &stop);
                        reader = reader + stop;
                }

                response->nxt = ret.answer;
                ret.answer = response;
        }

        for (int i = 0; i < ntohs(req->auth_count); i++)
        {
                response = malloc(sizeof(struct dns_res_record));
                if (!response)
                {
                        perror("dns:malloc response");
                        goto fail;
                }

                response->name = dns_fmt_name(reader, buff, &stop);
                reader += stop;

                response->resource = (struct dns_rec_data *)(reader);
                reader += sizeof(struct dns_rec_data);

                response->rdata = dns_fmt_name(reader, buff, &stop);
                reader += stop;

                // printf("Auth nameserver: %s\n", response->name);
                // printf("Auth nameserver rdata: %s\n", response->rdata);

                response->nxt = ret.auth;
                ret.auth = response;
        }

        for (int i = 0; i < ntohs(req->add_count); i++)
        {
                response = malloc(sizeof(struct dns_res_record));
                if (!response)
                {
                        perror("dns:malloc response");
                        goto fail;
                }

                response->name = dns_fmt_name(reader, buff, &stop);
                reader += stop;

                response->resource = (struct dns_rec_data *)(reader);
                reader += sizeof(struct dns_rec_data);

                if (ntohs(response->resource->type) == A || ntohs(response->resource->type) == AAAA)
                {
                        response->rdata = (char *)malloc(ntohs(response->resource->len));
                        for (int j = 0; j < ntohs(response->resource->len); j++)
                                response->rdata[j] = reader[j];
                        reader += ntohs(response->resource->len);
                }
                else
                {
                        response->rdata = dns_fmt_name(reader, buff, &stop);
                        reader += stop;
                }

                // printf("add rec name: %s\nadd rec data %d %d %d %d\n",
                //        response->name,
                //        ntohs(response->resource->class),
                //        ntohs(response->resource->ttl),
                //        ntohs(response->resource->type),
                //        ntohs(response->resource->len));

                response->nxt = ret.additional;
                ret.additional = response;
        }

        return ret;

fail:

        printf("Fail ecountered\n");
        return (struct dns_response){NULL, NULL, NULL};
}

int send_tcp_dns_request(char *resolver, char *host)
{
        uint8_t buff[1024];
        char dhcp[INET_ADDRSTRLEN];
        int fd = construct_ip4_sock(resolver, 6000, PORT_DNS, SOCK_STREAM);
        get_dns_resolver(dhcp);
        struct dns_response dns_response = {NULL, NULL, NULL};

        while (1)
        {
                uint16_t req_len = format_dns_request(buff + 2, A, host, ITER);
                *(uint16_t *)buff = htons(req_len);

                tcp_send_all(fd, buff, req_len + 2);
                memset(buff, 0, sizeof(req_len + 2));

                sleep(1);

                tcp_dns_recv_all(fd, buff, sizeof buff);
                fsync(fd);
                close(fd);
                sleep(1);

                free_dns_response(dns_response);
                dns_response = parse_dns_response(buff + 2);

                if (dns_response.answer)
                {
                        printf("Print got answer\n");
                        free_dns_response(dns_response);
                        break;
                }

                if (!dns_response.auth)
                {
                        printf("No more nameservers\n");
                        free_dns_response(dns_response);
                        break;
                }

                memset(buff, 0, sizeof buff);

                struct dns_res_record *auth = dns_response.auth;

                fd = construct_ip4_sock(dhcp, 6000, PORT_DNS, SOCK_STREAM);

                // resolve hostname (rdata) and set loop resolver
                // addr.sin_addr.s_addr = inet_addr(dhcp);

                req_len = format_dns_request(buff + 2, A, auth->rdata, RECURSE);
                *(uint16_t *)buff = htons(req_len);

                tcp_send_all(fd, buff, req_len + 2);
                memset(buff, 0, sizeof(req_len + 2));

                sleep(1);

                tcp_dns_recv_all(fd, buff, sizeof buff);

                fsync(fd);
                close(fd);
                sleep(1);

                char ip_str[INET_ADDRSTRLEN];

                free_dns_response(dns_response);
                dns_response = parse_dns_response(buff + 2);
                if (dns_response.answer)
                {
                        printf("Got answer record\n");
                        uint32_t *p;
                        p = (uint32_t *)dns_response.answer->rdata;
                        inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN);
                        printf("resolved ip is -> %s", ip_str);
                }
                else
                {
                        break;
                }

                fd = construct_ip4_sock(ip_str, 6000, PORT_DNS, SOCK_STREAM);
                memset(buff, 0, sizeof buff);
        }

        close(fd);

        sleep(1);

        return 0;
}

int send_udp_dns_request(char *resolver, char *host)
{

        uint8_t buff[65536];
        char dhcp[INET_ADDRSTRLEN];
        memset(buff, 0, sizeof(buff));
        get_dns_resolver(dhcp);

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
        addr.sin_port = htons(PORT_DNS);

        struct dns_response responses = {NULL, NULL, NULL};
        // iter through dns infra
        // send dns query -> get auth nameserver -> resolve -> iter
        while (1)
        {

                size_t len = format_dns_request(buff, A, host, ITER);

                if (sendto(fd, buff, len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
                {
                        perror("sendto failed");
                }
                sleep(1);

                memset(buff, 0, sizeof buff);

                socklen_t plen = sizeof(struct sockaddr_in);
                if (recvfrom(fd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &plen) < 0)
                {
                        perror("dns:recv_failed");
                }
                free_dns_response(responses);
                struct dns_response responses = parse_dns_response(buff);
                if (responses.answer)
                {
                        free_dns_response(responses);
                        break;
                }

                // Did not get answer, resolve auth nameserver for next part of stack
                if (!responses.auth)
                {

                        break;
                }

                struct dns_res_record *auth = responses.auth;

                // resolve hostname (rdata) and set loop resolver
                addr.sin_addr.s_addr = inet_addr(dhcp);
                len = format_dns_request(buff, A, auth->rdata, RECURSE);

                if (sendto(fd, buff, len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
                {
                        perror("sendto failed");
                }

                sleep(1);

                memset(buff, 0, sizeof buff);

                if (recvfrom(fd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &plen) < 0)
                {
                        perror("dns:recv_failed");
                }
                free_dns_response(responses);
                responses = parse_dns_response(buff);
                if (responses.answer)
                {
                        printf("Got answer record\n");
                        uint32_t *p;
                        p = (uint32_t *)responses.answer->rdata;
                        addr.sin_addr.s_addr = (*p); //working without ntohl
                }
                else
                {
                        free_dns_response(responses);
                        break;
                }
                memset(buff, 0, sizeof buff);
        }

        close(fd);

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

        memset(&payload[4], 0, 36);

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

        //ipv6 or ipv4
        if (get_ipstr_type(host) == 6)
        {
                fd = construct_ip6_sock(host, locport, PORT_NTP, SOCK_DGRAM);
        }
        else
        {
                fd = construct_ip4_sock(host, locport, PORT_NTP, SOCK_DGRAM);
        }
        if (fd < 0)
        {
                return -1;
        }

        int resp = udp_retry_send(fd, request, sizeof(request), response, sizeof(response));

        switch (resp)
        {
        case -1:
                fprintf(stderr, "ntp request errored out");
                break;
        case 0:
                printf("ntp did NOT receive response from node");
                break;
        case 1:
                fprintf(stderr, "ntp did receive response from node");
                break;

        default:
                break;
        }

        return 0;
}

static int send_ind_ntp_probe(int fd, char *host, struct sockaddr *addr, ssize_t addr_size, int locport, int ttl)
{

        struct udphdr *udp;
        uint8_t request[4096];

        memset(request, 0, sizeof(request));

        udp = (struct udphdr *)format_raw_iphdr(
            host,
            request,
            sizeof(struct udphdr) + 48,
            IPPROTO_UDP,
            ttl);

        udp->uh_sport = htons(locport);
        udp->uh_dport = htons(PORT_NTP);
        udp->uh_ulen = htons(sizeof(struct udphdr) + 48);
        udp->check = 0;

        uint8_t *payload = (uint8_t *)(++udp);
        format_ntp_request(payload);
        
        if (sendto(fd, request, (payload + 48 - request), 0, addr, addr_size) < 0)
        {
                perror("ntpprobe: failed to send\n");
                return -1;
        }

        return 0;
}

int send_udp_ntp_probe(char *host, int locport)
{

        struct sockaddr addr;
        struct timespec rst = HALF_S;
        int ipver = get_ipstr_type(host);
        int sock_type = (ipver == 4) ? AF_INET : AF_INET6;
        int sock_opt = (ipver == 4) ? IPPROTO_IP : IPPROTO_IPV6;
        int icmp_ver = (ipver == 4) ? IPPROTO_ICMP : IPPROTO_ICMPV6;
        int sock_hdr = (ipver == 4) ? IP_HDRINCL : IPV6_HDRINCL;

        ssize_t addr_size;

        if (sock_type == AF_INET)
        {
                struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
                inet_pton(AF_INET, host, &addr4->sin_addr.s_addr);
                addr_size = sizeof(struct sockaddr_in);
        }
        else if (sock_type == AF_INET6)
        {
                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
                inet_pton(AF_INET6, host, &addr6->sin6_addr);
                addr_size = sizeof(struct sockaddr_in6);
        }

        int fd = socket(sock_type, SOCK_RAW, IPPROTO_UDP);
        int ttlfd = socket(sock_type, SOCK_RAW, icmp_ver);

        int err = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        err |= fcntl(ttlfd, F_SETFL, fcntl(ttlfd, F_GETFL, 0) | O_NONBLOCK);

        if (err)
        {
                perror("ntp_probe:socket non block set\n");
                close(fd);
                close(ttlfd);
                return -1;
        }

        /* IP_HDRINCL to tell the kernel that headers are included in the packet */
        int one = 1;
        const int *val = &one;
        if (setsockopt(fd, sock_opt, sock_hdr, val, sizeof(one)) < 0)
        {
                printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
                return -1;
        }

        for (int i = 1; i < MAX_TTL; i++)
        {
                for (int j = 0; j < 5; j++)
                {
                        send_ind_ntp_probe(fd, host, &addr, addr_size, 6000, i);
                        nanosleep(&rst, &rst);
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

        printf("Did not recieve response from host\n");
        return -1;

exit:

        printf("did recieve response from host\n");
        return 0;
}

/* Dns compression utils */

static char *dns_fmt_name(unsigned char *reader, unsigned char *buffer, int *count)
{
        char *name;
        unsigned int p = 0, jumped = 0, offset;
        int i, j;

        *count = 1;
        name = (char *)malloc(256);

        name[0] = '\0';

        //read the names in 3www6google3com format
        while (*reader != 0)
        {
                if (*reader >= 192)
                {
                        offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
                        reader = buffer + offset - 1;
                        jumped = 1; //we have jumped to another location so counting wont go up!
                }
                else
                {
                        name[p++] = *reader;
                }

                reader = reader + 1;

                if (jumped == 0)
                {
                        *count = *count + 1; //if we havent jumped to another location then we can count up
                }
        }

        name[p] = '\0'; //string complete
        if (jumped == 1)
        {
                *count = *count + 1; //number of steps we actually moved forward in the packet
        }

        //now convert 3www6google3com0 to www.google.com
        for (i = 0; i < (int)strlen((const char *)name); i++)
        {
                p = name[i];
                for (j = 0; j < (int)p; j++)
                {
                        name[i] = name[i + 1];
                        i = i + 1;
                }
                name[i] = '.';
        }
        name[i - 1] = '\0'; //remove the last dot
        return name;
}

static void dns_name_fmt(uint8_t *dns, uint8_t *host)
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
