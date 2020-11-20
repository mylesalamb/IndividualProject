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
static uint8_t *format_raw_iphdr(uint8_t *buff, struct sockaddr_storage *addr, socklen_t addr_size, ssize_t request_len, int proto, int ttl);

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
        // Nothign to do, just trace path to host to see if it responds
        return defer_raw_tracert(host, NULL, 0, locport, PORT_HTTP, IPPROTO_TCP);
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
        if (!host)
                return 1;
        // Nothign to do, just trace path to host to see if it responds
        return defer_raw_tracert(host, NULL, 0, locport, PORT_DNS, IPPROTO_TCP);
}

int send_udp_dns_probe(char *host, char *ws, int locport)
{
        uint8_t buff[512], *end_ptr;
        if (!host || !ws)
                return 1;

        end_ptr = format_dns_request(ws, buff);

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

        end_ptr = format_ntp_request(buff);

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
        // Nothign to do, just trace path to host to see if it responds
        return defer_raw_tracert(host, NULL, 0, locport, PORT_HTTP, IPPROTO_TCP);
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

        if (addr->ss_family != AF_INET || addr->ss_family != AF_INET6)
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
                return 1;
        }

        fd = socket(addr->ss_family, SOCK_RAW, socktype);

        if (fd < 0)
        {
                fprintf(stderr, "contruct raw sock: socket creation");
                return 1;
        }
        if(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
        {
                fprintf(stderr, "construct_rawsock_to_host:nonblock");
                return 1;
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
                        return 1;
                }
        }

        return fd;
}

static int get_host_ipv6_addr(struct in6_addr *host)
{
        int ret = 0;
        struct ifaddrs *ifa;
        char debug[INET6_ADDRSTRLEN];

        static struct in6_addr cache_ret;
        static int cache = 0;

        if (cache)
        {
                memcpy(host, &cache_ret, sizeof(struct in6_addr));
                return 0;
        }

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
                inet_ntop(AF_INET6, &in6->sin6_addr, debug, sizeof(debug));
                printf("ip_str was: %s", debug);

                memcpy(host, &in6->sin6_addr, sizeof(struct in6_addr));
                memcpy(&cache_ret, &in6->sin6_addr, sizeof(struct in6_addr));
                cache = 1;
                ret = 1;
                break;
        }

        freeifaddrs(ifa);
        printf("get ipv6 addrs returned\n");
        return ret;
}

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
                        ret = check_ip4_response(fd, ttlfd, (struct sockaddr_in*)addr);
                }
                else if (addr->ss_family == AF_INET6)
                {
                        ret = check_ip6_response(fd, ttlfd, (struct sockaddr_in6*)addr);
                }

                if(ret == 2)
                {
                        return 0;
                }
        }
        return -1;
}

/**
 * Check both the fd, and icmp fd for responses across traceroute
 * 
 * returns:
 *      2  -> got response from intended host
 *      1  -> Got icmp ttl exceeded
 *     -1  -> Error response on an fd
 */
static int check_ip4_response(int fd, int ttlfd, struct sockaddr_in *srv_addr)
{
        int ret;
        uint8_t buff[512];
        struct iphdr *ip;
        struct icmphdr *icmp;

        ret = recvfrom(ttlfd, buff, sizeof buff, 0, NULL, NULL);
        if (ret < 0)
                return ret;

        ip = (struct iphdr *)buff;
        icmp = (struct icmphdr *)(buff + sizeof(struct iphdr));

        if (icmp->code == ICMP_EXC_TTL)
                return 1;

        ret = recvfrom(fd, buff, sizeof buff, 0, NULL, NULL);
        if (ret < 0)
                return ret;

        ip = (struct iphdr *)buff;

        if (!memcmp(&ip->saddr, &srv_addr->sin_addr, sizeof(struct in_addr)))
                return 2;

        return 0;
}
static int check_ip6_response(int fd, int ttlfd, struct sockaddr_in6 *srv_addr)
{
        int ret;
        uint8_t buff[512];
        struct icmp6_hdr *icmp;

        // check if we got an icmp ttl exceeded
        ret = recvfrom(ttlfd, buff, sizeof buff, 0, NULL, NULL);
        if (ret < 0)
                return ret;

        icmp = (struct icmp6_hdr *)buff;
        if (icmp->icmp6_type == ICMP6_TIME_EXCEEDED &&
            icmp->icmp6_code == ICMP6_TIME_EXCEED_TRANSIT)
        {
                printf("got time exceeded\n");
                return 1;
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
                        return 2;
                }
        }

        return 0;
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

static uint8_t *format_raw_iphdr(uint8_t *buff, struct sockaddr_storage *addr, socklen_t addr_size, ssize_t request_len, int proto, int ttl)
{
        struct iphdr *ip4 = (struct iphdr *)buff;
        struct ipv6hdr *ip6 = (struct ipv6hdr *)buff;

        if (!buff || !addr)
                return NULL;

        if (addr->ss_family == AF_INET)
        {
                // replace with a memcpy
                memcpy(&ip4->daddr, &((struct sockaddr_in *)addr)->sin_addr, sizeof(struct in_addr));
                inet_pton(AF_INET, "0.0.0.0", &(ip4->saddr));

                ip4->ihl = 5;
                ip4->version = 4;
                ip4->tot_len = htons(sizeof(struct iphdr) + request_len);
                ip4->id = htons(54321);
                ip4->ttl = ttl;
                ip4->protocol = proto;
        }
        else if (addr->ss_family == AF_INET6)
        {
                //replace with a memcpy
                memcpy(&ip6->daddr, &((struct sockaddr_in6 *)addr)->sin6_addr, sizeof(struct in6_addr));
                if (get_host_ipv6_addr(&ip6->saddr) != 1)
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

static int defer_raw_tracert(char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport, int proto)
{

        int fd, icmpfd, err;
        struct sockaddr_storage srv_addr;
        socklen_t srv_addr_size;

        struct timespec rst = UDP_DLY;

        uint8_t pkt[512];

        err = host_to_sockaddr(host, extport, &srv_addr, &srv_addr_size);
        if (err)
        {
                fprintf(stderr, "defer_raw: host_to_sockaddr");
                return 1;
        }

        fd = contruct_rawsock_to_host(&srv_addr, proto);
        if (fd < 0)
        {
                fprintf(stderr, "defer_raw_tracert: bad fd");
                return 1;
        }

        icmpfd = construct_icmp_sock(&srv_addr);

        for (int i = 1; i < MAX_TTL; i++)
        {
                uint8_t *offset = format_raw_iphdr(pkt, &srv_addr, srv_addr_size, buff_len, proto, i);
                memcpy(offset, buff, buff_len);
                for (int j = 0; j < MAX_UDP; j++)
                {
                        int ret;
                        sendto(fd, pkt, offset + buff_len - pkt, 0, (struct sockaddr *)&srv_addr, srv_addr_size);
                        nanosleep(&rst, &rst);
                        check_raw_response(fd, icmpfd, &srv_addr);
                        if (ret == 0)
                        {
                        }
                        else if (ret == 1)
                        {
                        }
                        else
                        {
                        }
                }
        }

        close(fd);
        close(icmpfd);
        return 0;
}