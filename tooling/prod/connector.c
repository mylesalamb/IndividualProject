#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <linux/ipv6.h>

#include <ifaddrs.h>

#include <net/if.h>

#include <arpa/inet.h>

#define PORT_NTP 123
#define PORT_HTTP 80
#define PORT_DNS 53

#define MAX_TTL 50
#define MAX_UDP 5

#define UDP_DLY (struct timespec){0, 500000000}

#define DNS_A_RECORD 1
#define DNS_RECURSIVE 1

#define HTTP_REQ "GET /index.html HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
const size_t HTTP_REQ_LEN = sizeof(HTTP_REQ) / sizeof(char);

/* handle ipv4 and ipv6 as nicely as possible */
static int ip_ver_str(char *host);
static int host_to_sockaddr(char *host, int extport, struct sockaddr_storage *addr, socklen_t *addr_size);
static int construct_sock_to_host(struct sockaddr_storage *addr, socklen_t *addr_size, int locport, int sock_type);

/* request formatters so we can nicely stack requests together */
static uint8_t *format_dns_request(char *ws, uint8_t *buff);
static uint8_t *format_ntp_request(uint8_t *buff);
static uint8_t *format_raw_iphdr(uint8_t *buff, struct sockaddr_storage *addr, socklen_t addr_size);

/* underlying request handlers to take care of repeated socket interactions */
static int defer_tcp_connection(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport);
static int defer_udp_exchnage(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport);

static int tcp_send_all(int fd, uint8_t *buff, size_t len);

int send_tcp_http_request(char *host, char *ws, int locport)
{
        uint8_t buff[512];

        if (!host || !ws)
        {
                fprintf(stderr, "send_tcp_http_request: bad arguments\n");
                return 1;
        }

        sprintf((char *)buff, HTTP_REQ, ws);
        return defer_tcp_connection(host, buff, strlen((char *)buff), locport, PORT_HTTP);
}

int send_tcp_http_probe(char *host, int locport)
{
        printf("Not implemented\n");
        return 0;
}

int send_tcp_dns_request(char *host, char *ws, int locport)
{
        uint8_t buff[512];
        uint8_t *base_ptr, *end_ptr;

        if(!host || !ws)
        {
                fprintf(stderr, "send_tcp_dns_request: bad arguements\n");
                return 1;
        }

        // get space for the length field of the request
        uint16_t *len = buff;
        base_ptr = buff + 2;

        end_ptr = format_dns_request(ws, base_ptr);
        *len = htons((uint16_t)(end_ptr - base_ptr));

        return defer_tcp_connection(host, buff, end_ptr - buff, locport, PORT_DNS);
}

int send_udp_dns_request(char *host, char *ws, int locport)
{
        uint8_t buff[512], *end_ptr;

        if(!host || !ws)
        {
                fprintf(stderr, "send_udp_dns_request\n");
                return 1;
        }

        end_ptr = format_dns_request(ws, buff);
        return defer_udp_exchnage(host, buff, end_ptr - buff, locport, PORT_DNS);
}

int send_tcp_dns_probe(char *host, char *ws, int locport)
{
        printf("Not implemented\n");
        return 0;
}

int send_udp_dns_probe(char *host, char *ws, int locport)
{
        printf("Not implemented\n");
        return 0;
}

int send_udp_ntp_request(char *host, int locport)
{
        uint8_t buff[512], *end_ptr;
        if(!host)
                return 1;
        
        end_ptr = format_ntp_request(buff);
        return defer_udp_exchnage(fd, buff, end_ptr - buff, locport, PORT_NTP);
}

int send_tcp_ntp_request(char *host, int locport)
{
        uint8_t buff[512];

        if (!host)
                return 1;

        sprintf((char *)buff, HTTP_REQ, "ntp.pool.org");
        return defer_tcp_connection(host, buff, strlen((char *)buff), locport, PORT_HTTP);
}

int send_udp_ntp_probe(char *host, int locport)
{
        printf("Not implemented\n");
        return 0;
}

int send_tcp_ntp_probe(char *host, int locport)
{
        printf("Not implemented\n");
        return 0;
}

/* Generic socket abstractions */

/* Assume that ip strings are their normal forms */
static int ip_ver_str(char *host)
{
        if (!host)
                return 0;

        return strchr(host, '.') ? AF_INET : AF_INET6;
}
static int host_to_sockaddr(char *host, int extport, struct sockaddr_storage *addr, socklen_t *addr_size)
{
        int err = 0;
        int addr_family;

        if (!host || !addr || !addr_size)
                return 1;

        addr_family = ip_ver_str(host);

        if (addr_family == AF_INET)
        {
                struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
                addr4->sin_family = AF_INET;
                addr4->sin_port = htons(extport);
                err = inet_pton(AF_INET, host, &addr4->sin_addr);

                *addr_size = sizeof(struct sockaddr_in6);
        }
        else if (addr_family == AF_INET6)
        {
                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
                addr6->sin6_family = AF_INET6;
                addr6->sin6_port = htons(extport);
                err = inet_pton(AF_INET6, host, &addr6->sin6_addr);

                *addr_size = sizeof(struct sockaddr_in6);
        }

        return err;
}

static int construct_sock_to_host(struct sockaddr_storage *addr, socklen_t *addr_size, int locport, int sock_type)
{
        int fd, sock_family;
        int opt = 1;

        struct sockaddr_storage host_addr;
        socklen_t host_addr_len;

        fd = socket(addr->ss_family, sock_type, 0);
        if (fd < 0)
        {
                perror("construct sock to host");
                return 1;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        {
                perror("construct sock to host: reuse port");
                close(fd);
                return -1;
        }

        if (addr->ss_family == AF_INET)
        {
                struct sockaddr_in *addr4 = (struct sockaddr_in *)&host_addr;
                addr4->sin_port = htons(locport);
                addr4->sin_family = addr->ss_family;
                addr4->sin_addr.s_addr = INADDR_ANY;
        }
        else if (addr->ss_family == AF_INET6)
        {
                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&host_addr;
                addr6->sin6_port = htons(locport);
                addr6->sin6_family = addr->ss_family;
                addr6->sin6_addr = in6addr_any;
        }
        else
        {
                fprintf(stderr, "socket family not supported\n");
                close(fd);
                return -1;
        }

        if (bind(fd, (struct sockaddr *)&host_addr, *addr_size))
        {
                perror("failed to bind");
                close(fd);
                return -1;
        }

        if (connect(fd, (struct sockaddr *)addr, *addr_size) == -1)
        {
                perror("construct socket to host: connect");
                close(fd);
                return -1;
        }

        if (sock_type == SOCK_DGRAM)
        {
                if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
                {
                        perror("construct sock to host: non block");
                        close(fd);
                        return -1;
                }
        }

        return fd;
}

/* Request formatters */

static void dns_name_fmt(uint8_t *dst, uint8_t *src);

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


static uint8_t *format_dns_request(char *ws, uint8_t *buff)
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
        req->rd = DNS_RECURSIVE;
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
        dns_name_fmt(qname, (uint8_t *)ws);

        qinfo = (struct dns_q *)&(buff[sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1)]); //fill it
        qinfo->qtype = htons(DNS_A_RECORD);
        qinfo->qclass = htons(1);

        return buff + (sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1) + sizeof(struct dns_q));
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
                        lock++;
                }
        }
        *dns++ = '\0';
}

static uint8_t *format_ntp_request(uint8_t *buff)
{
        if (!buff)
                return NULL;

        buff[0] = 0x23;
        buff[1] = 0x00;
        buff[2] = 0x06;
        buff[3] = 0x20;

        memset(&buff[4], 0, 36);

        // some point in time to reference
        uint64_t dummy_payload = 0x35eda5acd5c3ec15;
        memcpy(&buff[40], &dummy_payload, sizeof(dummy_payload));
        return buff + 48;
}

static uint8_t *format_raw_iphdr(uint8_t *buff, struct sockaddr_storage *addr, socklen_t addr_size)
{
        return NULL;
}

/* ensure that the end host receives the datagram, up to somepoint */
static int defer_udp_exchnage(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport)
{
        int fd;
        struct timespec rst = UDP_DLY;
        struct sockaddr_storage srv_addr;
        socklen_t srv_addr_len;

        uint8_t recv_buff[256];
        
        if(!buff || !host)
                return 1;

        host_to_sockaddr(host, extport, &srv_addr, &srv_addr_len);

        fd = construct_sock_to_host(
            &srv_addr,
            &srv_addr_len,
            locport,
            SOCK_DGRAM);

        if (fd < 0)
        {
                printf("defer_udp: bad fd\n");
                return 1;
        }

        int ret = 0;

        for(int i = 0; i < MAX_UDP; i++)
        {
                if(send(fd, buff, buff_len, 0) < 0)
                {
                        perror("defer_udp_exchange:send");
                        ret = 1;
                        break;
                }
                nanosleep(&rst, &rst);
                if(recv(fd,recv_buff, sizeof(recv_buff), 0) > 0){
                        break;
                }
        }
        sleep(2);

        return ret;
}

static int defer_tcp_connection(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport)
{
        int fd;
        struct sockaddr_storage srv_addr;
        socklen_t srv_addr_len;

        uint8_t recv_buff[100];

        if (!host || !buff)
                return 1;

        // get host to some sort of address, we dont really care
        host_to_sockaddr(host, extport, &srv_addr, &srv_addr_len);

        fd = construct_sock_to_host(
            &srv_addr,
            &srv_addr_len,
            locport,
            SOCK_STREAM);

        if (fd < 0)
        {
                printf("defer_tcp: bad fd\n");
                return 1;
        }

        tcp_send_all(fd, buff, buff_len);

        while (recv(fd, recv_buff, sizeof(recv_buff), 0) > 0)
                ;

        close(fd);
        sleep(2);
        

        return 0;
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
                        return 1;
                sent += ret;
                ptr = buff + sent;
        }

        return 0;
}
