/* weird pktinfo shenanigans*/
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <stddef.h>
#include <ev.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <linux/ipv6.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "lsquic.h"
#include "lsxpack_header.h"

#define PORT_NTP 123
#define PORT_HTTP 80
#define PORT_DNS 53
#define PORT_TLS 443

#define MAX_TTL 50
#define MAX_UDP 5
#define MAX_RAW 100

#define UDP_DLY \
        (struct timespec) { 0, 500000000 }

#define DNS_A_RECORD 1
#define DNS_RECURSIVE 1

#define HTTP_REQ "GET /index.html HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
const size_t HTTP_REQ_LEN = sizeof(HTTP_REQ) / sizeof(char);

/* handle ipv4 and ipv6 as nicely as possible */
static int ip_ver_str(char *host);
static int host_to_sockaddr(char *host, int extport, struct sockaddr_storage *addr, socklen_t *addr_size);

static int construct_sock_to_host(struct sockaddr_storage *addr, socklen_t *addr_size, int locport, int sock_type);
static int contruct_rawsock_to_host(struct sockaddr_storage *addr, int socktype);
static int construct_icmp_sock(struct sockaddr_storage *addr);

static int get_host_ipv6_addr(struct in6_addr *dst);

static int check_raw_response(int fd, int ttlfd, struct sockaddr_storage *srv_addr);
static int check_ip4_response(int fd, int ttlfd, struct sockaddr_in *srv_addr);
static int check_ip6_response(int fd, int ttlfd, struct sockaddr_in6 *srv_addr);

/* request formatters so we can nicely stack requests together */
static uint8_t *format_dns_request(char *ws, uint8_t *buff);
static uint8_t *format_ntp_request(uint8_t *buff);
static uint8_t *format_udp_header(uint8_t *buff, uint16_t len, uint16_t sport, uint16_t dport);
static uint8_t *format_tcp_header(uint8_t *buff, uint16_t sport, uint16_t dport, uint8_t flags);
static uint8_t *format_ip_header(uint8_t *buff, struct sockaddr_storage *addr, socklen_t addr_size, ssize_t request_len, int proto, int ttl);

/* underlying request handlers to take care of repeated socket interactions */
static int defer_tcp_connection(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport);
static int defer_udp_exchnage(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport);
static int defer_raw_tracert(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport, int proto);
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
        if (!host)
                return 1;
        uint8_t buff[64], *end_ptr;
        end_ptr = format_tcp_header(buff, locport, PORT_HTTP, 0x01);
        return defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_HTTP, IPPROTO_TCP);
}

int send_tcp_dns_request(char *host, char *ws, int locport)
{
        uint8_t buff[512];
        uint8_t *base_ptr, *end_ptr;

        if (!host || !ws)
        {
                fprintf(stderr, "send_tcp_dns_request: bad arguements\n");
                return 1;
        }

        // get space for the length field of the request
        uint16_t *len = (uint16_t *)buff;
        base_ptr = buff + 2;

        end_ptr = format_dns_request(ws, base_ptr);
        *len = htons((uint16_t)(end_ptr - base_ptr));

        return defer_tcp_connection(host, buff, end_ptr - buff, locport, PORT_DNS);
}

int send_udp_dns_request(char *host, char *ws, int locport)
{
        uint8_t buff[512], *end_ptr;

        if (!host || !ws)
        {
                fprintf(stderr, "send_udp_dns_request\n");
                return 1;
        }

        end_ptr = format_dns_request(ws, buff);
        return defer_udp_exchnage(host, buff, end_ptr - buff, locport, PORT_DNS);
}

int send_tcp_dns_probe(char *host, char *ws, int locport)
{
        printf("dns probe code called\n");
        if (!host)
                return 1;
        uint8_t buff[64], *end_ptr;
        end_ptr = format_tcp_header(buff, locport, PORT_DNS, 0x01);
        return defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_DNS, IPPROTO_TCP);
}

int send_udp_dns_probe(char *host, char *ws, int locport)
{
        uint8_t buff[512], *end_ptr;
        if (!host || !ws)
                return 1;

        uint8_t *payload = buff + sizeof(struct udphdr);
        end_ptr = format_dns_request(ws, payload);
        format_udp_header(buff, end_ptr - payload, locport, PORT_DNS);

        return defer_raw_tracert(
            host,
            buff,
            end_ptr - buff,
            locport,
            PORT_DNS,
            IPPROTO_UDP);
}

int send_udp_ntp_request(char *host, int locport)
{
        uint8_t buff[512], *end_ptr;
        if (!host)
                return 1;

        end_ptr = format_ntp_request(buff);
        return defer_udp_exchnage(host, buff, end_ptr - buff, locport, PORT_NTP);
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
        uint8_t buff[512], *end_ptr;

        if (!host)
                return 1;

        end_ptr = format_ntp_request(buff + sizeof(struct udphdr));
        format_udp_header(buff, 48, locport, PORT_NTP);

        return defer_raw_tracert(
            host,
            buff,
            end_ptr - buff,
            locport,
            PORT_NTP,
            IPPROTO_UDP);
}

int send_tcp_ntp_probe(char *host, int locport)
{
        if (!host)
                return 1;
        uint8_t buff[64], *end_ptr;
        end_ptr = format_tcp_header(buff, locport, PORT_HTTP, 0x01);
        return defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_HTTP, IPPROTO_TCP);
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
        printf("host is %s\n", host);

        if (!host || !addr || !addr_size)
        {
                printf("hts failed precond\n");
                return 1;
        }

        addr_family = ip_ver_str(host);

        if (addr_family == AF_INET)
        {
                printf("ipv4 path\n");
                struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
                addr4->sin_family = AF_INET;
                addr4->sin_port = htons(extport);
                err = inet_pton(AF_INET, host, &addr4->sin_addr);

                *addr_size = sizeof(struct sockaddr_in);
        }
        else if (addr_family == AF_INET6)
        {
                printf("ipv6 path\n");

                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
                memset(addr6, 0, sizeof(struct sockaddr_in6));
                addr6->sin6_family = AF_INET6;
                addr6->sin6_port = htons(extport);
                err = inet_pton(AF_INET6, host, &addr6->sin6_addr);

                *addr_size = sizeof(struct sockaddr_in6);
        }

        if (err != 1)
        {
                printf("inet pton err\n");
                return 1;
        }

        return 0;
}

static int construct_sock_to_host(struct sockaddr_storage *addr, socklen_t *addr_size, int locport, int sock_type)
{
        int fd;
        int opt = 1;

        struct sockaddr_storage host_addr;

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
        // give the same pre conditions to all sending functions
        // We dont change hosts on sending, so this is fine
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

static int construct_icmp_sock(struct sockaddr_storage *addr)
{
        int fd, icmp_ver;

        if (!addr)
                return -1;

        if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6)
                return -1;

        icmp_ver = (addr->ss_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;
        fd = socket(addr->ss_family, SOCK_RAW, icmp_ver);
        if (fd < 0)
                return fd;

        int err = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        if (err)
        {
                fprintf(stderr, "construct icmp sock: non block");
                close(fd);
                return -1;
        }

        return fd;
}

static int contruct_rawsock_to_host(struct sockaddr_storage *addr, int socktype)
{
        int fd;
        int one = 1;

        int sock_opt;
        int sock_hdr;

        if (!addr)
                return -1;

        if (addr->ss_family == AF_INET)
        {
                sock_opt = IPPROTO_IP;
                sock_hdr = IP_HDRINCL;
        }
        else if (addr->ss_family == AF_INET6)
        {
                sock_opt = IPPROTO_IPV6;
                sock_hdr = IPV6_HDRINCL;
        }
        else
        {
                fprintf(stderr, "contruct raw sock: socket family not supported");
                return -1;
        }

        fd = socket(addr->ss_family, SOCK_RAW, socktype);

        if (fd < 0)
        {
                fprintf(stderr, "contruct raw sock: socket creation");
                return -1;
        }
        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
        {
                fprintf(stderr, "construct_rawsock_to_host:nonblock");
                return -1;
        }
        if (setsockopt(fd, sock_opt, sock_hdr, &one, sizeof(one)) < 0)
        {
                perror("construct_rawsock: IP(V6)_HDRINCL");
                return -1;
        }

        if (addr->ss_family == AF_INET6)
        {
                if (setsockopt(fd, sock_opt, IPV6_RECVPKTINFO, &one, sizeof(one)) < 0)
                {
                        perror("construct_rawsock:recvmsg sockopt");
                        return -1;
                }
        }

        return fd;
}

static int get_host_ipv6_addr(struct in6_addr *host)
{
        int ret = 1;
        struct ifaddrs *ifa;

        // static struct in6_addr cache_ret;
        // static int cache = 0;

        // if (cache)
        // {
        //         memcpy(host, &cache_ret, sizeof(struct in6_addr));
        //         return 0;
        // }

        if (getifaddrs(&ifa) == -1)
        {
                perror("getifaddrs failed");
                return 1;
        }

        for (struct ifaddrs *ifa_i = ifa; ifa_i; ifa_i = ifa_i->ifa_next)
        {
                if (!(ifa_i->ifa_addr->sa_family == AF_INET6))
                        continue;

                // we dont want down interfaces
                if (!(ifa_i->ifa_flags & IFF_UP))
                        continue;

                if ((ifa_i->ifa_flags & IFF_LOOPBACK))
                        continue;

                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ifa_i->ifa_addr;
                if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr))
                {
                        printf("caught link local\n");
                        continue;
                }

                memcpy(host, &in6->sin6_addr, sizeof(struct in6_addr));
                //memcpy(&cache_ret, &in6->sin6_addr, sizeof(struct in6_addr));
                //cache = 1;
                ret = 0;
                break;
        }

        freeifaddrs(ifa);
        printf("get ipv6 addrs returned\n");
        return ret;
}
/**
 * Check responses from raw sockets
 * 
 * returns:
 *      0: got repsonse from host
 *      1: got some icmp ttl exceeded
 *      -1: otherwise errored
 */
static int check_raw_response(int fd, int ttlfd, struct sockaddr_storage *addr)
{

        if (!addr)
                return -1;

        if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6)
        {
                fprintf(stderr, "check raw response: socket family not supported\n");
                return -1;
        }

        int i = 0;
        while (i++ < MAX_RAW)
        {
                int ret;
                if (addr->ss_family == AF_INET)
                {
                        ret = check_ip4_response(fd, ttlfd, (struct sockaddr_in *)addr);
                }
                else if (addr->ss_family == AF_INET6)
                {
                        ret = check_ip6_response(fd, ttlfd, (struct sockaddr_in6 *)addr);
                }

                // try spin again if we dont get anything back
                if (ret == -1)
                        continue;

                // otherwise return what we saw
                return ret;
        }
        return -1;
}

/**
 * Check both the fd, and icmp fd for responses across traceroute
 * 
 * returns:
 *      0  -> got response from intended host
 *      1  -> Got icmp ttl exceeded
 *     -1  -> Error response on an fd, or no valued responses
 */
static int check_ip4_response(int fd, int ttlfd, struct sockaddr_in *srv_addr)
{
        uint8_t buff[512];
        struct iphdr *ip;
        struct icmphdr *icmp;

        if (recvfrom(ttlfd, buff, sizeof buff, 0, NULL, NULL) > 0)
        {
                printf("got some icmp traffic\n");
                ip = (struct iphdr *)buff;
                icmp = (struct icmphdr *)(buff + sizeof(struct iphdr));

                if (icmp->code == ICMP_EXC_TTL)
                {
                        printf("was ttl exceed\n");
                        return 1;
                }
                if (icmp->type == ICMP_DEST_UNREACH)
                {
                        printf("Was dest unreach\n");
                        return 2;
                }
        }

        if (recvfrom(fd, buff, sizeof buff, 0, NULL, NULL) > 0)
        {

                printf("Got response from somewhere");
                ip = (struct iphdr *)buff;
                if (!memcmp(&ip->saddr, &srv_addr->sin_addr, sizeof(struct in_addr)))
                {
                        printf("wasform host\n");
                        return 0;
                }
        }

        return -1;
}
static int check_ip6_response(int fd, int ttlfd, struct sockaddr_in6 *srv_addr)
{
        uint8_t buff[512];
        struct icmp6_hdr *icmp;

        // check if we got an icmp ttl exceeded
        if (recvfrom(ttlfd, buff, sizeof buff, 0, NULL, NULL) > 0)
        {
                printf("got icmp traffic\n");
                icmp = (struct icmp6_hdr *)buff;
                if (icmp->icmp6_type == ICMP6_TIME_EXCEEDED &&
                    icmp->icmp6_code == ICMP6_TIME_EXCEED_TRANSIT)
                {
                        printf("got time exceeded\n");
                        return 1;
                }
        }

        // Otherwise check if we got a response from the host

        struct sockaddr_in6 cname;
        memset(&cname, 0, sizeof(cname));

        char cmbuf[0x200];
        struct msghdr mh = {
            .msg_name = &cname,
            .msg_namelen = sizeof(cname),
            .msg_control = cmbuf,
            .msg_controllen = sizeof(cmbuf)};

        if (recvmsg(fd, &mh, 0) < 0)
        {
                return -1;
        }

        for (
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
            cmsg != NULL;
            cmsg = CMSG_NXTHDR(&mh, cmsg))
        {
                // ignore the control headers that don't match what we want
                if (cmsg->cmsg_level != IPPROTO_IPV6 ||
                    cmsg->cmsg_type != IPV6_PKTINFO)
                {
                        continue;
                }
                CMSG_DATA(cmsg);
                printf("addrlen was %d\n", mh.msg_namelen);

                // at this point, peeraddr is the source sockaddr
                if (!memcmp(&cname.sin6_addr, &srv_addr->sin6_addr, sizeof(struct in6_addr)))
                {

                        printf("was from host\n");
                        return 0;
                }
        }

        return -1;
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

static uint8_t *format_udp_header(uint8_t *buff, uint16_t len, uint16_t sport, uint16_t dport)
{
        struct udphdr *hdr;

        if (!buff)
                return NULL;

        hdr = (struct udphdr *)buff;
        hdr->uh_dport = htons(dport);
        hdr->uh_sport = htons(sport);
        hdr->uh_ulen = htons(len + sizeof(struct udphdr));
        hdr->check = 0;

        return buff + sizeof(struct udphdr);
}
static uint8_t *format_tcp_header(uint8_t *buff, uint16_t sport, uint16_t dport, uint8_t flags)
{
        struct tcphdr *hdr;

        srand(time(NULL));

        if (!buff)
                return NULL;

        hdr = (struct tcphdr *)buff;
        hdr->source = htons(sport);
        hdr->dest = htons(dport);
        hdr->seq = rand();
        hdr->ack_seq = (flags & 0x02) ? 1 : 0;
        hdr->doff = 5;
        hdr->syn = flags & 0x01;
        hdr->rst = (flags & 0x02) ? 1 : 0;
        hdr->ack = (flags & 0x02) ? 1 : 0;
        hdr->window = htons(1000);

        return buff + sizeof(struct tcphdr);
}

static uint8_t *format_ip_header(uint8_t *buff, struct sockaddr_storage *addr, socklen_t addr_size, ssize_t request_len, int proto, int ttl)
{
        struct iphdr *ip4 = (struct iphdr *)buff;
        struct ipv6hdr *ip6 = (struct ipv6hdr *)buff;

        if (!buff || !addr)
                return NULL;

        if (addr->ss_family == AF_INET)
        {
                memcpy(&ip4->daddr, &((struct sockaddr_in *)addr)->sin_addr, sizeof(struct in_addr));
                inet_pton(AF_INET, "0.0.0.0", &(ip4->saddr));

                ip4->ihl = 5;
                ip4->version = 4;
                ip4->tot_len = htons(sizeof(struct iphdr) + request_len);
                ip4->id = htons(54321);
                ip4->ttl = ttl;
                ip4->check = 0;
                ip4->protocol = proto;

                return buff + sizeof(struct iphdr);
        }
        else if (addr->ss_family == AF_INET6)
        {
                //replace with a memcpy
                memcpy(&ip6->daddr, &((struct sockaddr_in6 *)addr)->sin6_addr, sizeof(struct in6_addr));
                if (get_host_ipv6_addr(&ip6->saddr) == 1)
                {
                        fprintf(stderr, "fmt_raw_ip_hdr:get ip6 addr\n");
                        return NULL;
                }

                ip6->version = 6;
                ip6->flow_lbl[2] = 0xfc;
                ip6->payload_len = htons(request_len);
                ip6->nexthdr = proto;
                ip6->hop_limit = ttl;

                return buff + sizeof(struct ipv6hdr);
        }

        fprintf(stderr, "sock family not supported\n");
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

        if (!buff || !host)
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

        for (int i = 0; i < MAX_UDP; i++)
        {
                if (send(fd, buff, buff_len, 0) < 0)
                {
                        perror("defer_udp_exchange:send");
                        ret = 1;
                        break;
                }
                nanosleep(&rst, &rst);
                if (recv(fd, recv_buff, sizeof(recv_buff), 0) > 0)
                {
                        break;
                }
        }
        close(fd);
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
        printf("construct sock\n");
        fd = construct_sock_to_host(
            &srv_addr,
            &srv_addr_len,
            locport,
            SOCK_STREAM);
        printf("construct sock end\n");
        if (fd < 0)
        {
                printf("defer_tcp: bad fd\n");
                return 1;
        }
        printf("tpc-send");
        tcp_send_all(fd, buff, buff_len);
        printf("send-wait on recieve");
        while (recv(fd, recv_buff, sizeof(recv_buff), 0) > 0)
                ;

        close(fd);
        sleep(4);

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

static int defer_raw_tracert(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport, int proto)
{

        int fd, icmpfd, err;
        struct sockaddr_storage srv_addr;
        socklen_t srv_addr_size;
        struct timespec rst = UDP_DLY;
        uint8_t pkt[1024];

        if (!buff)
                return 1;

        err = host_to_sockaddr(host, 0, &srv_addr, &srv_addr_size);
        if (err)
        {
                fprintf(stderr, "defer_raw: host_to_sockaddr\n");
                return 1;
        }

        fd = contruct_rawsock_to_host(&srv_addr, proto);
        if (fd < 0)
        {
                fprintf(stderr, "defer_raw_tracert: bad fd\n");
                return 1;
        }

        icmpfd = construct_icmp_sock(&srv_addr);
        if (fd < 0)
        {
                fprintf(stderr, "defer_raw_tracert: bad icmp fd\n");
                return 1;
        }

        for (int i = 1; i < MAX_TTL; i++)
        {
                uint8_t *offset = format_ip_header(pkt, &srv_addr, srv_addr_size, buff_len, proto, i);
                if(!offset)
                        goto unreachable;
                memcpy(offset, buff, buff_len);
                for (int j = 0; j < MAX_UDP; j++)
                {
                        int len = (offset - pkt) + buff_len;
                        printf("len is %d\n", len);
                        int ret;
                        ret = sendto(fd, pkt, len, 0, (struct sockaddr *)&srv_addr, srv_addr_size);
                        if (ret < 0)
                        {
                                perror("send failed");
                                continue;
                        }

                        nanosleep(&rst, &rst);
                        ret = check_raw_response(fd, icmpfd, &srv_addr);
                        if (ret == 0)
                        {
                                printf("Got some response from host\n");
                                goto response;
                        }
                        else if (ret == 1)
                        {
                                printf("Got a ttl exceed\n");
                                break;
                        }
                        else if (ret == 2)
                        {
                                goto unreachable;
                        }
                        else
                        {
                                fprintf(stderr, "defer_raw_tracert:check_raw_response\n");
                        }
                }
        }

        close(fd);
        close(icmpfd);
        return 1;

response:
        sleep(2);
        close(fd);
        close(icmpfd);
        return 0;

unreachable:
        sleep(2);
        close(fd);
        close(icmpfd);
        return 1;

}
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static FILE *s_log_fh;

struct h3cli
{
        int h3cli_sock_fd;  /* socket */
        ev_io h3cli_sock_w; /* socket watcher */
        ev_timer h3cli_timer;
        struct ev_loop *h3cli_loop;
        lsquic_engine_t *h3cli_engine;
        const char *h3cli_method;
        const char *h3cli_path;
        const char *h3cli_hostname;
        lsquic_conn_t *h3cli_conn;
        struct sockaddr_storage h3cli_local_sas;
};

static void h3cli_process_conns(struct h3cli *);

static int
h3cli_log_buf(void *ctx, const char *buf, size_t len)
{
        FILE *out = ctx;
        fwrite(buf, 1, len, out);
        fflush(out);
        return 0;
}
static const struct lsquic_logger_if logger_if = {
    h3cli_log_buf,
};

static int s_verbose;
static void
LOG(const char *fmt, ...)
{
        if (s_verbose)
        {
                va_list ap;
                fprintf(s_log_fh, "LOG: ");
                va_start(ap, fmt);
                (void)vfprintf(s_log_fh, fmt, ap);
                va_end(ap);
                fprintf(s_log_fh, "\n");
        }
}

static int
h3cli_setup_control_message(struct msghdr *msg, const struct lsquic_out_spec *spec, unsigned char *buff, ssize_t buff_len)
{
        struct cmsghdr *cmsg;
        struct sockaddr_in *local_sa;
        struct sockaddr_in6 *local_sa6;
        struct in_pktinfo info;
        struct in6_pktinfo info6;
        size_t ctl_len;

        msg->msg_control = buff;
        msg->msg_controllen = buff_len;

        memset(buff, 0, buff_len);

        ctl_len = 0;
        cmsg = CMSG_FIRSTHDR(msg);

        if (AF_INET == spec->dest_sa->sa_family)
        {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_TOS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
        }
        else
        {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_TCLASS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
        }

        msg->msg_controllen = ctl_len;
        return 0;
}

static int
h3cli_packets_out(void *packets_out_ctx, const struct lsquic_out_spec *specs,
                  unsigned count)
{
        unsigned n;
        int fd, s = 0;
        struct msghdr msg;

        union
        {
                /* cmsg(3) recommends union for proper alignment */
                unsigned char buf[CMSG_SPACE(MAX(sizeof(struct in_pktinfo),
                                                 sizeof(struct in6_pktinfo))) +
                                  CMSG_SPACE(sizeof(int))];
                struct cmsghdr cmsg;
        } ancil;

        if (0 == count)
                return 0;

        n = 0;
        msg.msg_flags = 0;
        do
        {
                fd = (int)(uint64_t)specs[n].peer_ctx;
                msg.msg_name = (void *)specs[n].dest_sa;
                msg.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)),
                msg.msg_iov = specs[n].iov;
                msg.msg_iovlen = specs[n].iovlen;

                if (specs[n].ecn)
                {
                        h3cli_setup_control_message(&msg, &specs[n], ancil.buf, sizeof(ancil.buf));
                }
                else
                {
                        msg.msg_control = NULL;
                        msg.msg_controllen = 0;
                }

                s = sendmsg(fd, &msg, 0);
                if (s < 0)
                {
                        LOG("sendmsg failed: %s", strerror(errno));
                        break;
                }
                ++n;
        } while (n < count);

        if (n < count)
                LOG("could not send all of them"); /* TODO */

        if (n > 0)
                return n;
        else
        {
                assert(s < 0);
                return -1;
        }
}

static lsquic_conn_ctx_t *
h3cli_client_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn)
{
        struct h3cli *const h3cli = stream_if_ctx;
        LOG("created connection");
        lsquic_conn_make_stream(conn);
        return (void *)h3cli;
}

static void
h3cli_client_on_conn_closed(struct lsquic_conn *conn)
{
        struct h3cli *const h3cli = (void *)lsquic_conn_get_ctx(conn);

        LOG("client connection closed -- stop reading from socket");
        ev_io_stop(h3cli->h3cli_loop, &h3cli->h3cli_sock_w);
}

static lsquic_stream_ctx_t *
h3cli_client_on_new_stream(void *stream_if_ctx, struct lsquic_stream *stream)
{
        struct h3cli *h3cli = stream_if_ctx;
        LOG("created new stream, we want to write");
        lsquic_stream_wantwrite(stream, 1);
        /* return h3cli: we don't have any stream-specific context */
        return (void *)h3cli;
}

static void
h3cli_client_on_read(struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
        struct h3cli *h3cli = (struct h3cli *)h;
        ssize_t nread;
        unsigned char buf[0x1000];

        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nread > 0)
        {
                // fwrite(buf, 1, nread, stdout);
                // fflush(stdout);
        }
        else if (nread == 0)
        {
                LOG("read to end-of-stream: close connection");
                lsquic_stream_shutdown(stream, 0);
                lsquic_conn_close(lsquic_stream_conn(stream));
        }
        else
        {
                LOG("error reading from stream (%s) -- exit loop");
                ev_break(h3cli->h3cli_loop, EVBREAK_ONE);
        }
}

struct header_buf
{
        unsigned off;
        char buf[UINT16_MAX];
};

/* Convenience wrapper around somewhat involved lsxpack APIs */
int h3cli_set_header(struct lsxpack_header *hdr, struct header_buf *header_buf,
                     const char *name, size_t name_len, const char *val, size_t val_len)
{
        if (header_buf->off + name_len + val_len <= sizeof(header_buf->buf))
        {
                memcpy(header_buf->buf + header_buf->off, name, name_len);
                memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
                lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off,
                                           0, name_len, name_len, val_len);
                header_buf->off += name_len + val_len;
                return 0;
        }
        else
                return -1;
}

/* Send HTTP/3 request.  We don't support payload, just send the headers. */
static void
h3cli_client_on_write(struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
        struct h3cli *const h3cli = (void *)h;
        struct header_buf hbuf;
        struct lsxpack_header harray[5];
        struct lsquic_http_headers headers = {
            5,
            harray,
        };

        hbuf.off = 0;
#define V(v) (v), strlen(v)
        h3cli_set_header(&harray[0], &hbuf, V(":method"), V(h3cli->h3cli_method));
        h3cli_set_header(&harray[1], &hbuf, V(":scheme"), V("https"));
        h3cli_set_header(&harray[2], &hbuf, V(":path"), V(h3cli->h3cli_path));
        h3cli_set_header(&harray[3], &hbuf, V(":authority"),
                         V(h3cli->h3cli_hostname));
        h3cli_set_header(&harray[4], &hbuf, V("user-agent"), V("h3cli/lsquic"));

        if (0 == lsquic_stream_send_headers(stream, &headers, 0))
        {
                lsquic_stream_shutdown(stream, 1);
                lsquic_stream_wantread(stream, 1);
        }
        else
        {
                LOG("ERROR: lsquic_stream_send_headers failed: %s", strerror(errno));
                lsquic_conn_abort(lsquic_stream_conn(stream));
        }
}

static void
h3cli_client_on_close(struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
        LOG("stream closed");
}

static struct lsquic_stream_if h3cli_client_callbacks =
    {
        .on_new_conn = h3cli_client_on_new_conn,
        .on_conn_closed = h3cli_client_on_conn_closed,
        .on_new_stream = h3cli_client_on_new_stream,
        .on_read = h3cli_client_on_read,
        .on_write = h3cli_client_on_write,
        .on_close = h3cli_client_on_close,
};

static int
h3cli_set_nonblocking(int fd)
{
        int flags;

        flags = fcntl(fd, F_GETFL);
        if (-1 == flags)
                return -1;
        flags |= O_NONBLOCK;
        if (0 != fcntl(fd, F_SETFL, flags))
                return -1;

        return 0;
}

static void
h3cli_timer_expired(EV_P_ ev_timer *timer, int revents)
{
        h3cli_process_conns(timer->data);
}

static void
h3cli_process_conns(struct h3cli *h3cli)
{
        int diff;
        ev_tstamp timeout;

        ev_timer_stop(h3cli->h3cli_loop, &h3cli->h3cli_timer);
        lsquic_engine_process_conns(h3cli->h3cli_engine);

        if (lsquic_engine_earliest_adv_tick(h3cli->h3cli_engine, &diff))
        {
                if (diff >= LSQUIC_DF_CLOCK_GRANULARITY)
                        /* Expected case: convert to seconds */
                        timeout = (ev_tstamp)diff / 1000000;
                else if (diff <= 0)
                        /* It should not happen often that the next tick is in the past
             * as we just processed connections.  Avoid a busy loop by
             * scheduling an event:
             */
                        timeout = 0.0;
                else
                        /* Round up to granularity */
                        timeout = (ev_tstamp)LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
                LOG("converted diff %d usec to %.4lf seconds", diff, timeout);
                ev_timer_init(&h3cli->h3cli_timer, h3cli_timer_expired, timeout, 0.);
                ev_timer_start(h3cli->h3cli_loop, &h3cli->h3cli_timer);
        }
}

static int
h3cli_set_ecn(int fd, struct sockaddr *sa)
{
        int ret;
        int one = 1;

        if (sa->sa_family == AF_INET)
        {
                ret = setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &one, sizeof(one));
        }
        else
        {
                ret = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &one, sizeof(one));
        }

        if (ret)
        {
                perror("h3cli_set_ecn");
                return 1;
        }

        return 0;
}

static void
h3cli_proc_ancillary(struct msghdr *msg, struct sockaddr_storage *storage,
                     int *ecn)
{
        const struct in6_pktinfo *in6_pkt;
        struct cmsghdr *cmsg;

        for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
        {
                if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) || (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS))
                {
                        memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
                        *ecn &= IPTOS_ECN_MASK;
                }
        }
}

#if defined(IP_RECVORIGDSTADDR)
#define DST_MSG_SZ sizeof(struct sockaddr_in)
#else
#define DST_MSG_SZ sizeof(struct in_pktinfo)
#endif

#define ECN_SZ CMSG_SPACE(sizeof(int))

/* Amount of space required for incoming ancillary data */
#define CTL_SZ ECN_SZ

static void
h3cli_read_socket(EV_P_ ev_io *w, int revents)
{
        struct h3cli *const h3cli = w->data;
        ssize_t nread;
        int ecn;
        struct sockaddr_storage peer_sas, local_sas;
        unsigned char buf[0x1000];
        struct iovec vec[1] = {{buf, sizeof(buf)}};
        unsigned char ctl_buf[CTL_SZ];

        struct msghdr msg = {
            .msg_name = &peer_sas,
            .msg_namelen = sizeof(peer_sas),
            .msg_iov = vec,
            .msg_iovlen = 1,
            .msg_control = ctl_buf,
            .msg_controllen = sizeof(ctl_buf),
        };
        nread = recvmsg(w->fd, &msg, 0);
        if (-1 == nread)
        {
                if (!(EAGAIN == errno || EWOULDBLOCK == errno))
                        LOG("recvmsg: %s", strerror(errno));
                return;
        }

        local_sas = h3cli->h3cli_local_sas;
        ecn = 0;
        h3cli_proc_ancillary(&msg, &local_sas, &ecn);

        (void)lsquic_engine_packet_in(h3cli->h3cli_engine, buf, nread,
                                      (struct sockaddr *)&local_sas,
                                      (struct sockaddr *)&peer_sas,
                                      (void *)(uintptr_t)w->fd, ecn);

        h3cli_process_conns(h3cli);
}

static void *
keylog_open(void *ctx, lsquic_conn_t *conn)
{
        const char *const dir = ctx ? ctx : ".";
        const lsquic_cid_t *cid;
        FILE *fh;
        int sz;
        unsigned i;
        char id_str[MAX_CID_LEN * 2 + 1];
        char path[4096];
        static const char b2c[16] = "0123456789ABCDEF";

        cid = lsquic_conn_id(conn);
        for (i = 0; i < cid->len; ++i)
        {
                id_str[i * 2 + 0] = b2c[cid->idbuf[i] >> 4];
                id_str[i * 2 + 1] = b2c[cid->idbuf[i] & 0xF];
        }
        id_str[i * 2] = '\0';
        sz = snprintf(path, sizeof(path), "%s/%s.keys", dir, id_str);
        if ((size_t)sz >= sizeof(path))
        {
                LOG("WARN: %s: file too long", __func__);
                return NULL;
        }
        fh = fopen(path, "wb");
        if (!fh)
                LOG("WARN: could not open %s for writing: %s", path, strerror(errno));
        return fh;
}

static void
keylog_log_line(void *handle, const char *line)
{
        fputs(line, handle);
        fputs("\n", handle);
        fflush(handle);
}

static void
keylog_close(void *handle)
{
        fclose(handle);
}

static const struct lsquic_keylog_if keylog_if =
    {
        .kli_open = keylog_open,
        .kli_log_line = keylog_log_line,
        .kli_close = keylog_close,
};

int send_quic_http_request(char *host, char *sni, int locport, int ecn)
{
        struct lsquic_engine_api eapi;
        const char *cert_file = NULL, *key_file = NULL, *val, *port_str;
        int opt, version_cleared = 0, settings_initialized = 0;
        struct addrinfo hints, *res = NULL;
        socklen_t socklen;
        struct lsquic_engine_settings settings;
        struct h3cli h3cli;
        union
        {
                struct sockaddr sa;
                struct sockaddr_in addr4;
                struct sockaddr_in6 addr6;
        } addr;
        const char *key_log_dir = "data";
        key_file = "heelo.keys";
        char errbuf[0x100];

        s_log_fh = stdout;

        memset(&h3cli, 0, sizeof(h3cli));

        /* Need hostname, port, and path */
        h3cli.h3cli_method = "GET";
        h3cli.h3cli_hostname = sni;
        port_str = "443";
        h3cli.h3cli_path = "/";

        lsquic_set_log_level("debug");

        /* Resolve hostname */
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICSERV;
        if (0 != getaddrinfo(h3cli.h3cli_hostname, port_str, &hints, &res))
        {
                perror("getaddrinfo");
                return 1;
                ;
        }
        memcpy(&addr.sa, res->ai_addr, res->ai_addrlen);

        if (!settings_initialized)
                lsquic_engine_init_settings(&settings, LSENG_HTTP);

        /* At the time of this writing, using the loss bits extension causes
     * decryption failures in Wireshark.  For the purposes of the demo, we
     * override the default.
     */
        settings.es_ql_bits = 0;
        settings.es_versions = 1 << LSQVER_ID29;
        settings.es_ecn = ecn;

        /* Check settings */
        if (0 != lsquic_engine_check_settings(&settings, LSENG_HTTP,
                                              errbuf, sizeof(errbuf)))
        {
                LOG("invalid settings: %s", errbuf);
                return 1;
        }

        /* Initialize event loop */
        h3cli.h3cli_loop = EV_DEFAULT;
        h3cli.h3cli_sock_fd = socket(addr.sa.sa_family, SOCK_DGRAM, 0);
        /* Set up socket */
        if (h3cli.h3cli_sock_fd < 0)
        {
                perror("socket");
                return 1;
                ;
        }
        if (0 != h3cli_set_nonblocking(h3cli.h3cli_sock_fd))
        {
                perror("fcntl");
                return 1;
        }
        int one = 1;
        if (setsockopt(h3cli.h3cli_sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
        {
                perror("construct sock to host: reuse port");
                return -1;
        }

        if (ecn)
        {
                h3cli_set_ecn(h3cli.h3cli_sock_fd, (struct sockaddr *)&addr);
        }

        h3cli.h3cli_local_sas.ss_family = addr.sa.sa_family;
        struct sockaddr_in *loc_addr = &h3cli.h3cli_local_sas;
        loc_addr->sin_port = htons(6000);
        socklen = sizeof(h3cli.h3cli_local_sas);
        if (0 != bind(h3cli.h3cli_sock_fd,
                      (struct sockaddr *)&h3cli.h3cli_local_sas, socklen))
        {
                perror("bind");
                return 1;
        }
        ev_init(&h3cli.h3cli_timer, h3cli_timer_expired);
        ev_io_init(&h3cli.h3cli_sock_w, h3cli_read_socket, h3cli.h3cli_sock_fd, EV_READ);
        ev_io_start(h3cli.h3cli_loop, &h3cli.h3cli_sock_w);

        /* Initialize logging */
        setvbuf(s_log_fh, NULL, _IOLBF, 0);
        lsquic_logger_init(&logger_if, s_log_fh, LLTS_HHMMSSUS);

        /* Initialize callbacks */
        memset(&eapi, 0, sizeof(eapi));
        eapi.ea_packets_out = h3cli_packets_out;
        eapi.ea_packets_out_ctx = &h3cli;
        eapi.ea_stream_if = &h3cli_client_callbacks;
        eapi.ea_stream_if_ctx = &h3cli;
        if (key_log_dir)
        {
                eapi.ea_keylog_if = &keylog_if;
                eapi.ea_keylog_ctx = (void *)key_log_dir;
        }
        eapi.ea_settings = &settings;

        h3cli.h3cli_engine = lsquic_engine_new(LSENG_HTTP, &eapi);
        if (!h3cli.h3cli_engine)
        {
                LOG("cannot create engine");
                return 1;
        }

        h3cli.h3cli_timer.data = &h3cli;
        h3cli.h3cli_sock_w.data = &h3cli;
        h3cli.h3cli_conn = lsquic_engine_connect(
            h3cli.h3cli_engine, N_LSQVER,
            (struct sockaddr *)&h3cli.h3cli_local_sas, &addr.sa,
            (void *)(uintptr_t)h3cli.h3cli_sock_fd, /* Peer ctx */
            NULL, h3cli.h3cli_hostname, 0, NULL, 0, NULL, 0);
        if (!h3cli.h3cli_conn)
        {
                LOG("cannot create connection");
                return 1;
        }
        h3cli_process_conns(&h3cli);
        ev_run(h3cli.h3cli_loop, 0);
        lsquic_engine_destroy(h3cli.h3cli_engine);
        sleep(2);
        return 0;
}

int send_quic_http_probe(char *host, char *sni, int locport, int ecn)
{
        struct lsquic_engine_api eapi;
        const char *cert_file = NULL, *key_file = NULL, *val, *port_str;
        int opt, version_cleared = 0, settings_initialized = 0;
        struct addrinfo hints, *res = NULL;
        socklen_t socklen;
        struct lsquic_engine_settings settings;
        struct h3cli h3cli;
        union
        {
                struct sockaddr sa;
                struct sockaddr_in addr4;
                struct sockaddr_in6 addr6;
        } addr;
        const char *key_log_dir = NULL;
        char errbuf[0x100];

        s_log_fh = stderr;

        memset(&h3cli, 0, sizeof(h3cli));

        /* Need hostname, port, and path */
        h3cli.h3cli_method = "GET";
        h3cli.h3cli_hostname = sni;
        port_str = "443";
        h3cli.h3cli_path = "/";

        /* Resolve hostname */
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICSERV;
        if (0 != getaddrinfo(h3cli.h3cli_hostname, port_str, &hints, &res))
        {
                perror("getaddrinfo");
                return 1;
                ;
        }
        memcpy(&addr.sa, res->ai_addr, res->ai_addrlen);

        if (!settings_initialized)
                lsquic_engine_init_settings(&settings, LSENG_HTTP);

        /* At the time of this writing, using the loss bits extension causes
     * decryption failures in Wireshark.  For the purposes of the demo, we
     * override the default.
     */
        settings.es_ql_bits = 0;
        settings.es_versions = 1 << LSQVER_ID29;
        settings.es_ecn = ecn;

        /* Check settings */
        if (0 != lsquic_engine_check_settings(&settings, LSENG_HTTP,
                                              errbuf, sizeof(errbuf)))
        {
                LOG("invalid settings: %s", errbuf);
                return 1;
        }

        /* Initialize event loop */
        h3cli.h3cli_loop = EV_DEFAULT;
        h3cli.h3cli_sock_fd = socket(addr.sa.sa_family, SOCK_DGRAM, 0);

        /* Set up socket */
        if (h3cli.h3cli_sock_fd < 0)
        {
                perror("socket");
                return 1;
                
        }
        if (0 != h3cli_set_nonblocking(h3cli.h3cli_sock_fd))
        {
                perror("fcntl");
                return 1;
        }

        h3cli.h3cli_local_sas.ss_family = addr.sa.sa_family;
        struct sockaddr_in *loc_addr = &h3cli.h3cli_local_sas;
        loc_addr->sin_port = htons(6000);
        socklen = sizeof(struct sockaddr_in);
        if (0 != bind(h3cli.h3cli_sock_fd,
                      (struct sockaddr *)&h3cli.h3cli_local_sas, socklen))
        {
                perror("bind");
                return 1;
        }
        ev_init(&h3cli.h3cli_timer, h3cli_timer_expired);
        ev_io_init(&h3cli.h3cli_sock_w, h3cli_read_socket, h3cli.h3cli_sock_fd, EV_READ);
        ev_io_start(h3cli.h3cli_loop, &h3cli.h3cli_sock_w);

        /* Initialize logging */
        setvbuf(s_log_fh, NULL, _IOLBF, 0);
        lsquic_logger_init(&logger_if, s_log_fh, LLTS_HHMMSSUS);

        /* Initialize callbacks */
        memset(&eapi, 0, sizeof(eapi));
        eapi.ea_packets_out = h3cli_packets_out;
        eapi.ea_packets_out_ctx = &h3cli;
        eapi.ea_stream_if = &h3cli_client_callbacks;
        eapi.ea_stream_if_ctx = &h3cli;
        if (key_log_dir)
        {
                eapi.ea_keylog_if = &keylog_if;
                eapi.ea_keylog_ctx = (void *)key_log_dir;
        }
        eapi.ea_settings = &settings;

        h3cli.h3cli_engine = lsquic_engine_new(LSENG_HTTP, &eapi);
        if (!h3cli.h3cli_engine)
        {
                LOG("cannot create engine");
                return 1;
        }

        h3cli.h3cli_timer.data = &h3cli;
        h3cli.h3cli_sock_w.data = &h3cli;

        int ttlfd = construct_icmp_sock(&addr);
        if(ttlfd < 0)
                perror("bad sock");

        struct timespec rst = UDP_DLY;

        // todo add a flag that checks if we got anything back from
        // the server in one of the callbacks, to immediately close the connection

        for (int i = 1; i < MAX_TTL; i++)
        {
                printf("loop\n");
                uint8_t buff[500];
                setsockopt(h3cli.h3cli_sock_fd, IPPROTO_IP, IP_TTL, &i, sizeof(i));

                h3cli.h3cli_conn = lsquic_engine_connect(
                    h3cli.h3cli_engine, N_LSQVER,
                    (struct sockaddr *)&h3cli.h3cli_local_sas, &addr.sa,
                    (void *)(uintptr_t)h3cli.h3cli_sock_fd,
                    NULL, h3cli.h3cli_hostname, 0, NULL, 0, NULL, 0);
                h3cli_process_conns(&h3cli);
                sleep(2);
                lsquic_conn_close(h3cli.h3cli_conn);
                
        
        }

        
        ev_run(h3cli.h3cli_loop, 0);

        lsquic_engine_destroy(h3cli.h3cli_engine);
        sleep(2);
        return 0;
}