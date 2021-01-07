/* weird pktinfo shenanigans*/
#define _GNU_SOURCE

#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/ipv6.h>

#include "context.h"
#include "log.h"

#include "lsquic.h"
#include "lsxpack_header.h"

#define PORT_NTP 123
#define PORT_HTTP 80
#define PORT_DNS 53
#define PORT_TLS 443

#define MAX_TTL 50
#define MAX_UDP 3
#define MAX_RAW 100

//netinet doesnt define this for some reason
#define TH_ECE 0x40

// Any lower seems to cause the pcap capture to freak it
#define UDP_DLY \
  (struct timespec) { 0, 70000000 }

#define TCP_DLY \
  (struct timespec) { 0, 100000000 }

// Half second to ensure that tcp connections finish up
// and that pcap component has collected the last of the packets to file
#define CONN_DLY \
  (struct timespec) { 0, 500000000 }

#define DNS_A_RECORD 1
#define DNS_RECURSIVE 1

#define HTTP_REQ \
  "GET /index.html HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
const size_t HTTP_REQ_LEN = sizeof(HTTP_REQ) / sizeof(char);

/* handle ipv4 and ipv6 as nicely as possible */
static int bound_socket(char *host, enum conn_proto proto, socklen_t *addr_len, int locport);
static int host_to_sockaddr(char *host, int extport,
                            struct sockaddr_storage *addr,
                            socklen_t *addr_size);
static int construct_rawsock_to_host(struct sockaddr_storage *addr,
                                     int socktype, uint8_t flags);
static int construct_icmp_sock(struct sockaddr_storage *addr);

static int get_host_ipv6_addr(struct in6_addr *dst);

static int check_raw_response(int fd, int ttlfd,
                              struct sockaddr_storage *srv_addr, int locport, int pkt_type);
static int check_ip4_response(int fd, int ttlfd, struct sockaddr_in *srv_addr, int locport, int pkt_type);
static int check_ip6_response(int fd, int ttlfd, struct sockaddr_in6 *srv_addr, int locport, int pkt_type);

/* request formatters so we can nicely stack requests together */
static uint8_t *format_dns_request(char *ws, uint8_t *buff);
static uint8_t *format_ntp_request(uint8_t *buff);
static uint8_t *format_udp_header(uint8_t *buff, uint16_t len, uint16_t sport,
                                  uint16_t dport);
static uint8_t *format_tcp_header(uint8_t *buff, uint16_t sport, uint16_t dport,
                                  uint8_t flags);
static uint8_t *format_ip_header(uint8_t *buff, struct sockaddr_storage *addr,
                                 socklen_t addr_size, ssize_t request_len,
                                 int proto, int ttl);

static int send_generic_quic_request(int fd, char *host, char *sni, int locport,
                                     int ecn, int ttl);

/* underlying request handlers to take care of repeated socket interactions */
static int defer_tcp_connection(int fd, char *host, uint8_t *buff, ssize_t buff_len, int extport);
static int defer_tcp_path_probe(int fd, char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport, struct tcp_conn_t *conn);
static int defer_udp_exchnage(int fd, char *host, uint8_t *buff, ssize_t buff_len, int extport);
static int defer_raw_tracert(char *host, uint8_t *buff, ssize_t buff_len,
                             int locport, int extport, int proto);
static int tcp_send_all(int fd, uint8_t *buff, size_t len);

int get_port_number(struct sockaddr_storage *addr)
{
  if (addr->ss_family == AF_INET)
  {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
    return ntohs(addr4->sin_port);
  }
  else if (addr->ss_family == AF_INET6)
  {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
    return ntohs(addr6->sin6_port);
  }
  else
  {
    LOG_ERR("Address family not supported\n");
    return -1;
  }

  return -1;
}

/**
 * Just create a socket of the correct type, and return the correct port number
 */
int init_conn(char *host, enum conn_proto proto, int *fd, int *port)
{
  socklen_t len = sizeof(struct sockaddr_storage);
  struct sockaddr_storage remote_addr;

  int fd_ret = bound_socket(host, proto, &len, 0);
  if (fd_ret < 0)
  {
    LOG_ERR("create bound socket\n");
    return -1;
  }

  *fd = fd_ret;

  int ret = getsockname(*fd, (struct sockaddr *)&remote_addr, &len);
  if (ret < 0)
  {
    LOG_ERR("getsockname: %s\n", strerror(errno));
  }

  int loc_port = get_port_number(&remote_addr);

  *port = loc_port;
  return 0;
}

static int bound_socket(char *host, enum conn_proto proto, socklen_t *addr_len, int locport)
{

  int sock_family;
  int enable = 1;
  int ipver = ip_ver_str(host);
  struct sockaddr_storage loc_addr;
  socklen_t loc_len;

  switch (ipver)
  {
  case AF_INET:
    sock_family = AF_INET;
    struct sockaddr_in *loc4 = (struct sockaddr_in *)&loc_addr;
    loc4->sin_port = htons(locport);
    inet_pton(sock_family, "0.0.0.0", &loc4->sin_addr);
    loc4->sin_family = AF_INET;
    loc_len = sizeof(struct sockaddr_in);
    *addr_len = loc_len;
    break;
  case AF_INET6:
    sock_family = AF_INET6;
    struct sockaddr_in6 *loc6 = (struct sockaddr_in6 *)&loc_addr;
    int ret = get_host_ipv6_addr(&loc6->sin6_addr);
    if (ret)
      return -1;
    loc6->sin6_port = htons(locport);
    loc6->sin6_family = AF_INET6;
    loc_len = sizeof(struct sockaddr_in6);
    break;
  default:
    LOG_ERR("host is invalid\n");
    return -1;
  }

  struct sock_conf_t *sock_conf = &socket_conf[proto];

  int fd = socket(sock_family, sock_conf->sock_type, sock_conf->sock_protocol);
  if (fd < 0)
  {
    LOG_ERR("socket failed, returning %d\n", fd);
    return fd;
  }

  if (locport != 0)
  {
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
      LOG_ERR("set reuse port\n");
      close(fd);
      return -1;
    }
  }

  if (bind(fd, (struct sockaddr *)&loc_addr, loc_len) < 0)
  {
    LOG_ERR("Bind failed %s\n", strerror(errno));
    close(fd);
    return -1;
  }

  socklen_t len = sizeof(struct sockaddr_storage);
  getsockname(fd, (struct sockaddr_in *)&loc_addr, &len);

  return fd;
}

int apply_sock_opts(int fd, int sock_type, struct sockaddr *addr, socklen_t addrlen)
{
  if (fd < 0 || !addr || addrlen < 0)
  {
    LOG_ERR("Invalid args\n");
    return -1;
  }

  if (sock_type != SOCK_DGRAM && sock_type != SOCK_STREAM)
  {
    LOG_ERR("Invalid sock type\n");
    return -1;
  }

  if (connect(fd, addr, addrlen) < 0)
  {
    LOG_ERR("Connect failed %s\n", strerror(errno));
    return -1;
  }

  if (sock_type == SOCK_DGRAM)
  {
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
    {
      LOG_ERR("construct sock to host: non block\n");
      return -1;
    }
  }

  return 0;
}

int send_tcp_http_request(int fd, char *host, char *ws, int locport, int ecn, struct tcp_conn_t *conn)
{
  uint8_t buff[512];

  if (!host || !ws)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  sprintf((char *)buff, HTTP_REQ, ws);
  if (!ecn)
  {
    return defer_tcp_connection(fd, host, buff, strlen((char *)buff),
                                PORT_HTTP);
  }
  else
  {
    return defer_tcp_path_probe(fd, host, buff, strlen((char *)buff), locport, PORT_HTTP, conn);
  }
}

int send_tcp_http_probe(int fd, char *host, int locport)
{
  int ret;
  if (!host)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  uint8_t buff[64], *end_ptr;
  end_ptr = format_tcp_header(buff, locport, PORT_HTTP, 0x01);
  ret = defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_HTTP,
                          IPPROTO_TCP);
  close(fd);
  return ret;
}

int send_tcp_dns_request(int fd, char *host, char *ws, int locport, int ecn, struct tcp_conn_t *conn)
{
  uint8_t buff[512];
  uint8_t *base_ptr, *end_ptr;

  if (!host || !ws)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  // get space for the length field of the request
  uint16_t *len = (uint16_t *)buff;
  base_ptr = buff + 2;

  end_ptr = format_dns_request(ws, base_ptr);
  *len = htons((uint16_t)(end_ptr - base_ptr));

  if (!ecn)
  {
    return defer_tcp_connection(fd, host, buff, end_ptr - buff, PORT_DNS);
  }
  else
  {
    LOG_INFO("Calling tcp path probe");
    return defer_tcp_path_probe(fd, host, buff, end_ptr - buff, locport, PORT_DNS, conn);
  }
}

int send_udp_dns_request(int fd, char *host, char *ws, int locport)
{
  uint8_t buff[512], *end_ptr;

  if (!host || !ws)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  end_ptr = format_dns_request(ws, buff);
  return defer_udp_exchnage(fd, host, buff, end_ptr - buff, PORT_DNS);
}

int send_tcp_dns_probe(int fd, char *host, char *ws, int locport)
{
  int ret;
  if (!host)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }
  uint8_t buff[64], *end_ptr;
  end_ptr = format_tcp_header(buff, locport, PORT_DNS, 0x01);
  ret = defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_DNS,
                          IPPROTO_TCP);
  close(fd);
  return ret;
}

int send_udp_dns_probe(int fd, char *host, char *ws, int locport)
{
  int ret;
  uint8_t buff[512], *end_ptr;
  if (!host || !ws)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  uint8_t *payload = buff + sizeof(struct udphdr);
  end_ptr = format_dns_request(ws, payload);
  format_udp_header(buff, end_ptr - payload, locport, PORT_DNS);
  ret = defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_DNS,
                          IPPROTO_UDP);
  close(fd);
  return ret;
}

int send_udp_ntp_request(int fd, char *host, int locport)
{
  uint8_t buff[512], *end_ptr;
  if (!host)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  end_ptr = format_ntp_request(buff);
  return defer_udp_exchnage(fd, host, buff, end_ptr - buff, PORT_NTP);
}

int send_tcp_ntp_request(int fd, char *host, int locport, int ecn, struct tcp_conn_t *conn)
{
  uint8_t buff[512];

  if (!host)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  // servers in ntp pool are recomended to host a webserver pointing to here
  sprintf((char *)buff, HTTP_REQ, "ntp.pool.org");
  if (!ecn)
  {
    return defer_tcp_connection(fd, host, buff, strlen((char *)buff),
                                PORT_HTTP);
  }
  else
  {
    return defer_tcp_path_probe(fd, host, buff, strlen((char *)buff), locport, PORT_NTP, conn);
  }
}

int send_udp_ntp_probe(int fd, char *host, int locport)
{
  int ret;
  uint8_t buff[512], *end_ptr;

  if (!host)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  end_ptr = format_ntp_request(buff + sizeof(struct udphdr));
  format_udp_header(buff, 48, locport, PORT_NTP);

  ret = defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_NTP,
                          IPPROTO_UDP);
  close(fd);

  return ret;
}

int send_tcp_ntp_probe(int fd, char *host, int locport)
{
  int ret;
  if (!host)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }
  uint8_t buff[64], *end_ptr;
  end_ptr = format_tcp_header(buff, locport, PORT_HTTP, 0x01);
  ret = defer_raw_tracert(host, buff, end_ptr - buff, locport, PORT_HTTP,
                          IPPROTO_TCP);
  close(fd);
  return ret;
}

/* Generic socket abstractions */
static int host_to_sockaddr(char *host, int extport,
                            struct sockaddr_storage *addr,
                            socklen_t *addr_size)
{
  int err = 0;
  int addr_family;
  memset(addr, 0, sizeof(struct sockaddr_storage));

  if (!host || !addr || !addr_size)
  {
    LOG_ERR("bad arguments\n");
    return 1;
  }

  addr_family = ip_ver_str(host);

  if (addr_family == AF_INET)
  {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(extport);
    err = inet_pton(AF_INET, host, &addr4->sin_addr);

    *addr_size = sizeof(struct sockaddr_in);
  }
  else if (addr_family == AF_INET6)
  {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
    memset(addr6, 0, sizeof(struct sockaddr_in6));
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(extport);
    err = inet_pton(AF_INET6, host, &addr6->sin6_addr);

    *addr_size = sizeof(struct sockaddr_in6);
  }

  if (err != 1)
  {
    LOG_ERR("inet pton\n");
    return 1;
  }

  return 0;
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
    LOG_ERR("non block\n");
    close(fd);
    return -1;
  }

  return fd;
}

static int construct_rawsock_to_host(struct sockaddr_storage *addr,
                                     int socktype, uint8_t flags)
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
    LOG_ERR("socket family not supported\n");
    return -1;
  }

  fd = socket(addr->ss_family, SOCK_RAW, socktype);

  if (fd < 0)
  {
    LOG_ERR("socket creation\n");
    return -1;
  }
  if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
  {
    LOG_ERR("nonblock\n");
    return -1;
  }
  // dont include headers if we are probing the path
  if (!(flags & 0x01) && setsockopt(fd, sock_opt, sock_hdr, &one, sizeof(one)) < 0)
  {
    LOG_ERR("IP(V6)_HDRINCL\n");
    return -1;
  }

  if (addr->ss_family == AF_INET6)
  {
    if (setsockopt(fd, sock_opt, IPV6_RECVPKTINFO, &one, sizeof(one)) < 0)
    {
      LOG_ERR("recvmsg sockopt\n");
      return -1;
    }
  }

  return fd;
}

/* Cache the result, ifaddrs seems to exceptionally fail if called alot raising SIGABRT */
static int get_host_ipv6_addr(struct in6_addr *host)
{
  static int cache = 0;
  static struct in6_addr addr;
  int ret = 1;
  struct ifaddrs *ifa;

  if (cache)
  {
    struct in6_addr cmp;
    memset(&cmp, 0, sizeof cmp);

    if (!memcmp(&cmp, &addr, sizeof cmp))
    {
      return 1;
    }
    memcpy(host, &addr, sizeof(struct in6_addr));
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
      continue;
    }

    memcpy(host, &in6->sin6_addr, sizeof(struct in6_addr));
    memcpy(&addr, &in6->sin6_addr, sizeof(struct in6_addr));
    cache = 1;
    ret = 0;
    break;
  }
  freeifaddrs(ifa);

  if (!cache)
  {
    memset(&addr, 0, sizeof addr);
    cache = 1;
  }

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
static int check_raw_response(int fd, int ttlfd,
                              struct sockaddr_storage *addr, int locport, int pkt_type)
{

  if (!addr)
    return -1;

  if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6)
  {
    LOG_ERR("socket family not supported\n");
    return -1;
  }

  int i = 0;
  while (i++ < MAX_RAW)
  {
    int ret = -1;
    if (addr->ss_family == AF_INET)
    {
      ret = check_ip4_response(fd, ttlfd, (struct sockaddr_in *)addr, locport, pkt_type);
    }
    else if (addr->ss_family == AF_INET6)
    {
      ret = check_ip6_response(fd, ttlfd, (struct sockaddr_in6 *)addr, locport, pkt_type);
    }
    else
    {
      LOG_ERR("address family not supported\n");
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
static int check_ip4_response(int fd, int ttlfd, struct sockaddr_in *srv_addr, int locport, int pkt_type)
{
  uint8_t buff[1024];
  struct iphdr *ip = buff;
  struct icmphdr *icmp = buff;

  if (ttlfd > 0 && recvfrom(ttlfd, buff, sizeof buff, 0, NULL, NULL) > 0)
  {
    ip = (struct iphdr *)buff;
    icmp = (struct icmphdr *)(buff + sizeof(struct iphdr));

    if (icmp->code == ICMP_EXC_TTL)
    {
      return 1;
    }
    if (icmp->type == ICMP_DEST_UNREACH)
    {
      if (icmp->code == ICMP_UNREACH_HOST_PROHIB)
      {
        return 3;
      }
      return 2;
    }
  }

  if (fd > 0 && recvfrom(fd, buff, sizeof buff, 0, NULL, NULL) > 0)
  {
    struct tcphdr *tcp;
    struct udphdr *udp;

    if (ip->protocol != pkt_type)
    {
      return -1;
    }

    // calculate the offset to the data of the ip packet
    ssize_t len = ip->ihl;
    uint8_t *data_offset = (len * 4) + buff;
    uint16_t port_number = 0;

    ip = (struct iphdr *)buff;
    if (memcmp(&ip->saddr, &srv_addr->sin_addr, sizeof(struct in_addr)))
    {
      return -1;
    }
    LOG_INFO("Matched host addr\n");
    if (pkt_type == IPPROTO_TCP)
    {
      tcp = (struct tcphdr *)data_offset;
      port_number = tcp->dest;
    }
    else
    {
      udp = (struct udphdr *)data_offset;
      port_number = udp->dest;
    }

    if (ntohs(port_number) == locport)
    {
      LOG_INFO("Matched port numbers");
      return 0;
    }
  }
  return -1;
}
static int check_ip6_response(int fd, int ttlfd,
                              struct sockaddr_in6 *srv_addr, int locport, int pkt_type)
{
  uint8_t buff[512];
  struct icmp6_hdr *icmp;
  bool match_port = false;
  bool match_host = false;
  // check if we got an icmp ttl exceeded
  if (recvfrom(ttlfd, buff, sizeof buff, 0, NULL, NULL) > 0)
  {
    icmp = (struct icmp6_hdr *)buff;
    if (icmp->icmp6_type == ICMP6_TIME_EXCEEDED &&
        icmp->icmp6_code == ICMP6_TIME_EXCEED_TRANSIT)
    {
      return 1;
    }

    if (icmp->icmp6_type == ICMP6_DST_UNREACH &&
        icmp->icmp6_code == ICMP6_DST_UNREACH_ADMIN)
    {
      return 3;
    }
  }

  // Otherwise check if we got a response from the host
  struct iovec iov[1];
  uint8_t *iobuff;
  if (!(iobuff = calloc(1, 4096)))
  {
    LOG_INFO("calloc failed\n");
    return -1;
  }
  iov->iov_base = iobuff;
  iov->iov_len = 4096;

  struct sockaddr_in6 cname;
  memset(&cname, 0, sizeof(cname));

  char cmbuf[0x200];
  struct msghdr mh = {.msg_name = &cname,
                      .msg_namelen = sizeof(cname),
                      .msg_control = cmbuf,
                      .msg_controllen = sizeof(cmbuf),
                      .msg_iov = iov,
                      .msg_iovlen = 1};

  if (recvmsg(fd, &mh, 0) < 0)
  {
    free(iobuff);
    return -1;
  }

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(&mh, cmsg))
  {

    // ignore the control headers that don't match what we want
    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
    {
      CMSG_DATA(cmsg);
      // at this point, peeraddr is the source sockaddr
      if (!memcmp(&cname.sin6_addr, &srv_addr->sin6_addr,
                  sizeof(struct in6_addr)))
      {
        LOG_INFO("matched host\n");
        match_host = true;
        break;
      }
    }
  }

  struct tcphdr *tcp = (struct tcphdr *)iobuff;
  struct udphdr *udp = (struct udphdr *)iobuff;

  uint32_t port_number;

  if (pkt_type == IPPROTO_TCP)
  {
    port_number = tcp->dest;
  }
  if (pkt_type == IPPROTO_UDP)
  {

    port_number = udp->dest;
  }

  if (ntohs(port_number) == locport)
  {
    LOG_INFO("Matched port as well\n");
    match_port = true;
  }

  if (match_port && match_host)
  {
    free(iobuff);
    return 0;
  }

  free(iobuff);
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

  qinfo = (struct dns_q *)&(buff[sizeof(struct dns_hdr) +
                                 (strlen((const char *)qname) + 1)]); // fill it
  qinfo->qtype = htons(DNS_A_RECORD);
  qinfo->qclass = htons(1);

  return buff + (sizeof(struct dns_hdr) + (strlen((const char *)qname) + 1) +
                 sizeof(struct dns_q));
}

static void dns_name_fmt(uint8_t *dns, uint8_t *host)
{
  int lock = 0, i;
  char host_tmp[INET6_ADDRSTRLEN];
  strcpy(host_tmp, (char *)host);
  strcat(host_tmp, ".");

  for (i = 0; i < strlen((char *)host_tmp); i++)
  {
    if (host_tmp[i] == '.')
    {
      *dns++ = i - lock;
      for (; lock < i; lock++)
      {
        *dns++ = host_tmp[lock];
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

static uint8_t *format_udp_header(uint8_t *buff, uint16_t len, uint16_t sport,
                                  uint16_t dport)
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
static uint8_t *format_tcp_header(uint8_t *buff, uint16_t sport, uint16_t dport,
                                  uint8_t flags)
{
  struct tcphdr *hdr;
  //memset(buff, 0, sizeof(struct tcphdr));

  srand(time(NULL));

  if (!buff)
    return NULL;

  hdr = (struct tcphdr *)buff;
  hdr->source = htons(sport);
  hdr->dest = htons(dport);
  hdr->seq = rand();
  hdr->ack_seq = htonl((flags & 0x02) ? 1 : 0);
  hdr->doff = 5;
  hdr->syn = flags & 0x01;
  hdr->rst = (flags & 0x02) ? 1 : 0;
  hdr->ack = (flags & 0x02) ? 1 : 0;
  hdr->window = htons(1000);
  hdr->th_off = 5;

  return buff + sizeof(struct tcphdr);
}

static uint8_t *format_ip_header(uint8_t *buff, struct sockaddr_storage *addr,
                                 socklen_t addr_size, ssize_t request_len,
                                 int proto, int ttl)
{
  struct iphdr *ip4 = (struct iphdr *)buff;
  struct ipv6hdr *ip6 = (struct ipv6hdr *)buff;

  if (!buff || !addr)
    return NULL;

  if (addr->ss_family == AF_INET)
  {
    memcpy(&ip4->daddr, &((struct sockaddr_in *)addr)->sin_addr,
           sizeof(struct in_addr));
    inet_pton(AF_INET, "0.0.0.0", &(ip4->saddr));

    ip4->ihl = 5;
    ip4->version = 4;
    ip4->tot_len = htons(sizeof(struct iphdr) + request_len);
    ip4->id = htons(0);
    ip4->ttl = ttl;
    ip4->check = 0;
    ip4->protocol = proto;

    return buff + sizeof(struct iphdr);
  }
  else if (addr->ss_family == AF_INET6)
  {
    LOG_INFO("ip6 path\n");
    memcpy(&ip6->daddr, &((struct sockaddr_in6 *)addr)->sin6_addr,
           sizeof(struct in6_addr));
    if (get_host_ipv6_addr(&ip6->saddr) != 0)
    {
      LOG_ERR("get ipv6 addr\n");
      return NULL;
    }

    ip6->version = 6;
    ip6->flow_lbl[2] = 0xfc;
    ip6->payload_len = htons(request_len);
    ip6->nexthdr = proto;
    ip6->hop_limit = ttl;

    return buff + sizeof(struct ipv6hdr);
  }
  else
  {
    LOG_ERR("address family\n");
  }

  return NULL;
}

/* ensure that the end host receives the datagram, up to somepoint */
static int defer_udp_exchnage(int fd, char *host, uint8_t *buff, ssize_t buff_len, int extport)
{

  struct timespec rst = UDP_DLY;
  struct timespec dly = CONN_DLY;
  struct sockaddr_storage srv_addr;
  socklen_t srv_addr_len;

  uint8_t recv_buff[256];

  if (!buff || !host)
    return 1;

  host_to_sockaddr(host, extport, &srv_addr, &srv_addr_len);
  apply_sock_opts(fd, SOCK_DGRAM, (struct sockaddr *)&srv_addr, srv_addr_len);

  if (fd < 0)
  {
    LOG_ERR("bad fd\n");
    return 1;
  }

  int ret = 0;

  for (int i = 0; i < MAX_UDP; i++)
  {
    if (send(fd, buff, buff_len, 0) < 0)
    {
      LOG_ERR("send\n");
      ret = 1;
      break;
    }
    nanosleep(&rst, &rst);
    if (recv(fd, recv_buff, sizeof(recv_buff), 0) > 0)
    {
      LOG_INFO("Got response\n");
      break;
    }
  }
  close(fd);

  nanosleep(&dly, &dly);

  return ret;
}

static int defer_tcp_path_probe(int fd, char *host, uint8_t *buff, ssize_t buff_len, int locport, int extport, struct tcp_conn_t *conn)
{
  struct timespec dly = CONN_DLY;
  struct timespec rst = TCP_DLY;
  struct sockaddr_storage srv_addr, srv_addr_ono;
  socklen_t srv_addr_len;
  int rawfd;

  // seq, and ack for hijacking live tcp conn
  uint32_t tcp_seq, tcp_ack;
  uint8_t raw_buff[sizeof(struct tcphdr) + buff_len];

  if (!host || !buff){
    close(fd);
    return 1;
  }

  if (host_to_sockaddr(host, extport, &srv_addr, &srv_addr_len) ||
      host_to_sockaddr(host, 0, &srv_addr_ono, &srv_addr_len))
  {
    LOG_INFO("Host to sockaddr failed\n");
    close(fd);
    return 1;
  }

  // get host to some sort of address, connect call, so we should at least have
  // the seq value for the rawsock
  if (apply_sock_opts(fd, SOCK_STREAM, (struct sockaddr *)&srv_addr, srv_addr_len))
  {
    LOG_ERR("Apply sock opts failed\n");
    close(fd);
    return -1;
  }
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

  if (!(rawfd = construct_rawsock_to_host(&srv_addr, IPPROTO_TCP, 0x01)))
  {
    LOG_ERR("create probe fd\n");
    close(fd);
    return 1;
  }

  pthread_mutex_lock(&conn->mtx);
  if (!(conn->tcp_ack && conn->tcp_seq))
  {
    struct timespec wt;
    if (clock_gettime(CLOCK_REALTIME, &wt))
    {
      LOG_INFO("Get time failed\n");
      close(fd);
      close(rawfd);
      pthread_mutex_unlock(&conn->mtx);
    }

    wt.tv_nsec += 5000000;

    pthread_cond_timedwait(&conn->cv, &conn->mtx, &wt);

    if (!conn->tcp_ack || !conn->tcp_seq)
    {
      LOG_INFO("failed to catch ack\n");
      pthread_mutex_unlock(&conn->mtx);
      close(fd);
      close(rawfd);
      return -1;
    }
  }

  tcp_seq = conn->tcp_seq;
  tcp_ack = conn->tcp_ack;

  pthread_mutex_unlock(&conn->mtx);

  // quickly format the header to look like the next tcp header we should expect
  struct tcphdr *hdr = (struct tcphdr *)raw_buff;
  memset(hdr, 0, sizeof(struct tcphdr));
  hdr->syn = 0;
  hdr->ack = 1;
  hdr->window = htons(10000);
  hdr->doff = 5;
  hdr->seq = tcp_seq;
  hdr->ack_seq = tcp_ack;
  hdr->source = htons(locport);
  hdr->dest = htons(extport);
  memcpy(raw_buff + sizeof(struct tcphdr), buff, buff_len);

  ssize_t raw_buff_len = sizeof(struct tcphdr) + buff_len;

  for (int i = 1; i < MAX_TTL; i++)
  {
    if (srv_addr.ss_family == AF_INET)
    {
      setsockopt(rawfd, IPPROTO_IP, IP_TTL, &i, sizeof i);
    }
    else
    {
      setsockopt(rawfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &i, sizeof i);
    }
    for (int j = 0; j < 1; j++)
    {
      if (sendto(rawfd, raw_buff, raw_buff_len, 0, (struct sockaddr *)&srv_addr_ono, srv_addr_len) < 0)
      {
        LOG_INFO("send failed with: %s", strerror(errno));
      }
      else
      {
        LOG_INFO("send succeeded\n");
      }
      if (!check_raw_response(rawfd, -1, &srv_addr, locport, IPPROTO_TCP))
      {
        LOG_INFO("recieved response\n");
        close(fd);
        close(rawfd);
        nanosleep(&dly, &dly);
        return 0;
      }
    }
    nanosleep(&rst, &rst);
  }

  close(fd);
  close(rawfd);
  nanosleep(&dly, &dly);
  return 1;
}

static int defer_tcp_connection(int fd, char *host, uint8_t *buff, ssize_t buff_len,
                                int extport)
{

  struct timespec dly = CONN_DLY;
  struct sockaddr_storage srv_addr;
  socklen_t srv_addr_len;

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 250000;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv))
  {
    LOG_ERR("recv timeout\n");
  }

  uint8_t recv_buff[100];

  if (host_to_sockaddr(host, extport, &srv_addr, &srv_addr_len))
  {
    LOG_INFO("Host to sockaddr failed\n");
    close(fd);
    return 1;
  }

  if (!host || !buff)
    return 1;

  // get host to some sort of address
  if (apply_sock_opts(fd, SOCK_STREAM, (struct sockaddr *)&srv_addr, srv_addr_len))
  {
    LOG_ERR("Apply sock opts failed\n");
    close(fd);
    return -1;
  }

  if (fd < 0)
  {
    LOG_ERR("defer_tcp: bad fd\n");
    return 1;
  }
  tcp_send_all(fd, buff, buff_len);

  while (recv(fd, recv_buff, sizeof(recv_buff), 0) > 0)
  {
    
  }

  close(fd);
  nanosleep(&dly, &dly);

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

static int defer_raw_tracert(char *host, uint8_t *buff, ssize_t buff_len,
                             int locport, int extport, int proto)
{

  int fd, icmpfd, err;
  struct sockaddr_storage srv_addr, srv_addr_ono;
  socklen_t srv_addr_size;
  struct timespec rst = UDP_DLY;
  struct timespec dly = CONN_DLY;

  uint8_t pkt[1024];
  memset(pkt, 0, sizeof pkt);

  if (!buff)
    return 1;

  err = host_to_sockaddr(host, extport, &srv_addr, &srv_addr_size);
  err |= host_to_sockaddr(host, 0, &srv_addr_ono, &srv_addr_size);
  if (err)
  {
    LOG_ERR("host_to_sockaddr\n");
    return 1;
  }

  fd = construct_rawsock_to_host(&srv_addr, proto, 0x00);
  if (fd < 0)
  {
    LOG_ERR("bad fd\n");
    return 1;
  }

  icmpfd = construct_icmp_sock(&srv_addr);
  if (icmpfd < 0)
  {
    LOG_ERR("bad icmp fd\n");
    return 1;
  }

  for (int i = 1; i < MAX_TTL; i++)
  {
    uint8_t *offset =
        format_ip_header(pkt, &srv_addr, srv_addr_size, buff_len, proto, i);
    if (!offset)
      goto unreachable;
    memcpy(offset, buff, buff_len);
    for (int j = 0; j < MAX_UDP; j++)
    {
      int len = (offset - pkt) + buff_len;
      int ret;
      ret =
          sendto(fd, pkt, len, 0, (struct sockaddr *)&srv_addr_ono, srv_addr_size);
      if (ret < 0)
      {
        LOG_ERR("send failed, returning: %s\n", strerror(errno));
        continue;
      }

      nanosleep(&rst, &rst);
      ret = check_raw_response(fd, icmpfd, &srv_addr, locport, proto);
      if (ret == 0)
      {
        goto response;
      }
      else if (ret == 1)
      {
        break;
      }
      else if (ret == 2)
      {
        goto unreachable;
      }

      // Buffer is empty
      // Spin and send again
    }
  }

  close(fd);
  close(icmpfd);
  return 1;

response:

  nanosleep(&dly, &dly);
  close(fd);
  close(icmpfd);
  return 0;

unreachable:
  nanosleep(&dly, &dly);
  close(fd);
  close(icmpfd);
  return 1;
}

/**
 *  Copyright (c) 2020 LiteSpeed Technologies
 *  From here to the end of the file is an adopted version of the lsquic
 * tutorial https://github.com/dtikhonov/lsquic-tutorial
 *
 *  This code is licensed under the MIT License, which is compatible with this
 * project (under the same license)
 */

#define MAX(a, b) ((a) > (b) ? (a) : (b))

struct h3cli
{
  int h3cli_sock_fd;
  int seen_response;
  ev_io h3cli_sock_w;
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

static int h3cli_setup_control_message(struct msghdr *msg,
                                       const struct lsquic_out_spec *spec,
                                       unsigned char *buff, ssize_t buff_len)
{
  struct cmsghdr *cmsg;
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

static int h3cli_packets_out(void *packets_out_ctx,
                             const struct lsquic_out_spec *specs,
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
    msg.msg_namelen =
        (AF_INET == specs[n].dest_sa->sa_family ? sizeof(struct sockaddr_in)
                                                : sizeof(struct sockaddr_in6)),
    msg.msg_iov = specs[n].iov;
    msg.msg_iovlen = specs[n].iovlen;

    if (specs[n].ecn)
    {
      h3cli_setup_control_message(&msg, &specs[n], ancil.buf,
                                  sizeof(ancil.buf));
    }
    else
    {
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
    }

    s = sendmsg(fd, &msg, 0);
    if (s < 0)
    {
      LOG_ERR("sendmsg failed: %s\n", strerror(errno));
      break;
    }
    ++n;
  } while (n < count);

  if (n < count)
    LOG_INFO("could not send all of them\n");

  if (n > 0)
    return n;
  else
  {
    assert(s < 0);
    return -1;
  }
}

static lsquic_conn_ctx_t *h3cli_client_on_new_conn(void *stream_if_ctx,
                                                   struct lsquic_conn *conn)
{
  struct h3cli *const h3cli = stream_if_ctx;
  lsquic_conn_make_stream(conn);
  return (void *)h3cli;
}

static void h3cli_client_on_conn_closed(struct lsquic_conn *conn)
{
  struct h3cli *const h3cli = (void *)lsquic_conn_get_ctx(conn);
  ev_io_stop(h3cli->h3cli_loop, &h3cli->h3cli_sock_w);
}

static lsquic_stream_ctx_t *
h3cli_client_on_new_stream(void *stream_if_ctx, struct lsquic_stream *stream)
{
  struct h3cli *h3cli = stream_if_ctx;
  lsquic_stream_wantwrite(stream, 1);
  /* return h3cli: we don't have any stream-specific context */
  return (void *)h3cli;
}

static void h3cli_client_on_read(struct lsquic_stream *stream,
                                 lsquic_stream_ctx_t *h)
{
  struct h3cli *h3cli = (struct h3cli *)h;
  ssize_t nread;
  unsigned char buf[0x1000];

  nread = lsquic_stream_read(stream, buf, sizeof(buf));
  if (nread > 0)
  {
    h3cli->seen_response = 1;
  }
  else if (nread == 0)
  {
    lsquic_stream_shutdown(stream, 0);
    lsquic_conn_close(lsquic_stream_conn(stream));
  }
  else
  {
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
                     const char *name, size_t name_len, const char *val,
                     size_t val_len)
{
  if (header_buf->off + name_len + val_len <= sizeof(header_buf->buf))
  {
    memcpy(header_buf->buf + header_buf->off, name, name_len);
    memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
    lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off, 0,
                               name_len, name_len, val_len);
    header_buf->off += name_len + val_len;
    return 0;
  }
  else
    return -1;
}

/* Send HTTP/3 request.  We don't support payload, just send the headers. */
static void h3cli_client_on_write(struct lsquic_stream *stream,
                                  lsquic_stream_ctx_t *h)
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
    lsquic_conn_abort(lsquic_stream_conn(stream));
  }
}

static void h3cli_client_on_close(struct lsquic_stream *stream,
                                  lsquic_stream_ctx_t *h) {}

static struct lsquic_stream_if h3cli_client_callbacks = {
    .on_new_conn = h3cli_client_on_new_conn,
    .on_conn_closed = h3cli_client_on_conn_closed,
    .on_new_stream = h3cli_client_on_new_stream,
    .on_read = h3cli_client_on_read,
    .on_write = h3cli_client_on_write,
    .on_close = h3cli_client_on_close,
};

static void h3cli_timer_expired(EV_P_ ev_timer *timer, int revents)
{
  h3cli_process_conns(timer->data);
}

static void h3cli_process_conns(struct h3cli *h3cli)
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
      timeout = 0.0;
    else
      /* Round up to granularity */
      timeout = (ev_tstamp)LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
    ev_timer_init(&h3cli->h3cli_timer, h3cli_timer_expired, timeout, 0.);
    ev_timer_start(h3cli->h3cli_loop, &h3cli->h3cli_timer);
  }
}

static int h3cli_set_ecn(int fd, struct sockaddr *sa)
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

static void h3cli_proc_ancillary(struct msghdr *msg,
                                 struct sockaddr_storage *storage, int *ecn)
{
  struct cmsghdr *cmsg;

  for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
  {
    if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) ||
        (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS))
    {
      memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
      *ecn &= IPTOS_ECN_MASK;
    }
  }
}

struct keylog_ctx
{
};

#if defined(IP_RECVORIGDSTADDR)
#define DST_MSG_SZ sizeof(struct sockaddr_in)
#else
#define DST_MSG_SZ sizeof(struct in_pktinfo)
#endif

#define ECN_SZ CMSG_SPACE(sizeof(int))

/* Amount of space required for incoming ancillary data */
#define CTL_SZ ECN_SZ

static void h3cli_read_socket(EV_P_ ev_io *w, int revents)
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
      LOG_ERR("recvmsg: %s", strerror(errno));
    return;
  }

  local_sas = h3cli->h3cli_local_sas;
  ecn = 0;
  h3cli_proc_ancillary(&msg, &local_sas, &ecn);

  (void)lsquic_engine_packet_in(
      h3cli->h3cli_engine, buf, nread, (struct sockaddr *)&local_sas,
      (struct sockaddr *)&peer_sas, (void *)(uintptr_t)w->fd, ecn);

  h3cli_process_conns(h3cli);
}

static void *keylog_open(void *ctx, lsquic_conn_t *conn)
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
    LOG_INFO("file too long\n");
    return NULL;
  }
  fh = fopen(path, "wb");
  if (!fh)
    LOG_INFO("Could not open %s for writing: %s\n", path, strerror(errno));
  return fh;
}

static void keylog_log_line(void *handle, const char *line)
{
  fputs(line, handle);
  fputs("\n", handle);
  fflush(handle);
}

static void keylog_close(void *handle) { fclose(handle); }

static const struct lsquic_keylog_if keylog_if = {
    .kli_open = keylog_open,
    .kli_log_line = keylog_log_line,
    .kli_close = keylog_close,
};

int send_quic_http_request(int fd, char *host, char *sni, int locport, int ecn)
{
  int ret = send_generic_quic_request(fd, host, sni, locport, ecn, MAX_TTL);
  close(fd);
  return ret;
}

int send_quic_http_probe(int fd, char *host, char *sni, int locport, int ecn, struct quic_pkt_t *relay)
{
  int icmpfd;
  struct sockaddr_storage addr;
  socklen_t socklen;
  struct timespec dly = UDP_DLY;
  host_to_sockaddr(host, PORT_TLS, &addr, &socklen);
  apply_sock_opts(fd, SOCK_DGRAM, (struct sockaddr *)&addr, socklen);
  uint8_t buff[1024];

  icmpfd = construct_icmp_sock(&addr);
  if (icmpfd < 0)
  {
    LOG_ERR("icmp fd\n");
    close(fd);
  }

  pthread_mutex_lock(&relay->mtx);
  uint8_t *pkt_relay = relay->pkt_relay;
  pthread_mutex_unlock(&relay->mtx);
  if (!pkt_relay)
  {
    LOG_INFO("Buffer packet to relay\n");
    send_generic_quic_request(fd, host, sni, locport, ecn, 1);

    pthread_mutex_lock(&relay->mtx);
    pkt_relay = relay->pkt_relay;
    pthread_mutex_unlock(&relay->mtx);
  }
  if (!pkt_relay)
  {
    LOG_ERR("Failed to catch pkt to relay\n");
    return -1;
  }

  // get length of quic packet
  pthread_mutex_lock(&relay->mtx);
  ssize_t pkt_relay_len = relay->pkt_relay_len;
  pthread_mutex_unlock(&relay->mtx);

  LOG_INFO("Called with payload: %p (len %ul)\n", *pkt_relay, pkt_relay_len);

  // Probes only really care about modifications to the ECT fields
  // Hence relaying a buffered packet is likely fine

  for (int i = 1; i < MAX_TTL; i++)
  {

    if (ip_ver_str(host) == AF_INET)
    {
      setsockopt(fd, IPPROTO_IP, IP_TTL, &i, sizeof i);
    }
    else
    {
      setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &i, sizeof i);
    }

    for (int j = 0; j < MAX_UDP; j++)
    {
      if (send(fd, pkt_relay, pkt_relay_len, 0) < 0)
      {
        LOG_ERR("send failed: %s\n", strerror(errno));
        close(fd);
        close(icmpfd);
        return -1;
      }
      nanosleep(&dly, &dly);
      if (recv(fd, buff, sizeof buff, 0) > 0)
      {
        close(fd);
        close(icmpfd);
        return 0;
      }

      // Check the response for icmp responses
      if (addr.ss_family == AF_INET)
      {
        int ret = -1;
        int spin = 0;
        while (spin++ < 100 || ret != -1)
        {
          ret = check_ip4_response(-1, icmpfd, (struct sockaddr_in *)&addr, locport, IPPROTO_UDP);
        }
        // icmp host prohibited
        if (ret == 3)
        {
          goto fail;
        }
      }
      else if (addr.ss_family == AF_INET6)
      {
        int ret = -1;
        int spin = 0;
        while (spin++ < 100 || ret != -1)
        {
          ret = check_ip6_response(-1, icmpfd, (struct sockaddr_in6 *)&addr, locport, IPPROTO_UDP);
        }
        if (ret == 3)
        {
          goto fail;
        }
      }
    }
  }
fail:
  close(fd);
  close(icmpfd);
  return 1;
}

static int send_generic_quic_request(int fd, char *host, char *sni, int locport,
                                     int ecn, int ttl)
{
  struct lsquic_engine_api eapi;
  struct lsquic_engine_settings settings;
  struct h3cli h3cli;
  struct sockaddr_storage addr;
  socklen_t addr_len;
  const char *key_log_dir = "keystore";
  char errbuf[0x100];

  memset(&h3cli, 0, sizeof(h3cli));

  /* Need hostname, port, and path */
  h3cli.h3cli_method = "GET";
  h3cli.h3cli_hostname = sni;
  h3cli.h3cli_path = "/";

  // resolve host to sockaddr
  int ret = host_to_sockaddr(host, PORT_TLS, &addr, &addr_len);
  if (ret)
  {
    LOG_ERR("Host to sockaddr\n");
    return 1;
  }

  apply_sock_opts(fd, SOCK_DGRAM, (struct sockaddr *)&addr, addr_len);

  lsquic_engine_init_settings(&settings, LSENG_HTTP);

  settings.es_ql_bits = 0;
  settings.es_versions = 1 << LSQVER_ID29;
  settings.es_ecn = ecn;

  if (0 != lsquic_engine_check_settings(&settings, LSENG_HTTP, errbuf,
                                        sizeof(errbuf)))
  {
    LOG_INFO("invalid settings: %s\n", errbuf);
    return 1;
  }

  /* Initialize event loop */
  h3cli.h3cli_loop = EV_DEFAULT;
  h3cli.h3cli_sock_fd = fd;

  if (ecn)
  {
    h3cli_set_ecn(h3cli.h3cli_sock_fd, (struct sockaddr *)&addr);
  }

  h3cli.h3cli_local_sas.ss_family = addr.ss_family;

  ev_init(&h3cli.h3cli_timer, h3cli_timer_expired);
  ev_io_init(&h3cli.h3cli_sock_w, h3cli_read_socket, h3cli.h3cli_sock_fd,
             EV_READ);
  ev_io_start(h3cli.h3cli_loop, &h3cli.h3cli_sock_w);

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
    LOG_ERR("cannot create engine\n");
    return 1;
  }

  if (ip_ver_str(host) == AF_INET)
  {
    setsockopt(h3cli.h3cli_sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl);
  }
  else
  {
    setsockopt(h3cli.h3cli_sock_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof ttl);
  }

  h3cli.h3cli_timer.data = &h3cli;
  h3cli.h3cli_sock_w.data = &h3cli;
  h3cli.h3cli_conn = lsquic_engine_connect(
      h3cli.h3cli_engine, N_LSQVER, (struct sockaddr *)&h3cli.h3cli_local_sas,
      (struct sockaddr *)&addr,
      (void *)(uintptr_t)h3cli.h3cli_sock_fd, /* Peer ctx */
      NULL, h3cli.h3cli_hostname, 0, NULL, 0, NULL, 0);
  if (!h3cli.h3cli_conn)
  {
    LOG_ERR("cannot create connection\n");
    return 1;
  }
  h3cli_process_conns(&h3cli);

  ev_run(h3cli.h3cli_loop, 0);
  lsquic_engine_destroy(h3cli.h3cli_engine);
  sleep(1);
  ev_loop_destroy(h3cli.h3cli_loop);

  if (h3cli.seen_response)
    return 0;

  return -1;
}
