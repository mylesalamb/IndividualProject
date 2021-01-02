#ifndef CONNECTOR_H
#define CONNECTOR_H 1

#include <sys/socket.h>
#include "context.h"

int init_conn(char * host, enum conn_proto proto, int *fd, int *port);
int bound_socket(char *host, enum conn_proto proto, socklen_t *addr_len);
int get_port_number(struct sockaddr_storage *addr);


int send_tcp_http_request(int fd, char *host, char *ws, int locport, int ecn, uint8_t **pkt_relay, ssize_t *pkt_relay_len);
int send_tcp_http_probe(int fd, char *host, int locport);

int send_tcp_dns_request(int fd, char *host, char *ws, int locport, int ecn, uint8_t **pkt_relay, ssize_t *pkt_relay_len );
int send_udp_dns_request(int fd, char *host, char *ws, int locport);

int send_tcp_dns_probe(int fd, char *host, char *ws, int locport);
int send_udp_dns_probe(int fd, char *host, char *ws, int locport);

int send_udp_ntp_request(int fd, char *host, int locport);
int send_tcp_ntp_request(int fd, char *host, int locport, int ecn, uint8_t **pkt_relay, ssize_t *pkt_relay_len);

int send_udp_ntp_probe(int fd, char *host, int locport);
int send_tcp_ntp_probe(int fd, char *host, int locport);

int send_quic_http_request(int fd, char *host, char *sni, int locport, int ecn);
int send_quic_http_probe(int fd, char *host, char *sni, int locport, int ecn, uint8_t **pkt_relay, ssize_t *pkt_relay_len);

#endif