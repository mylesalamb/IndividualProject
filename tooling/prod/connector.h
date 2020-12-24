#ifndef CONNECTOR_H
#define CONNECTOR_H 1

#include "context.h"

int bound_socket(char *host, enum conn_proto proto);

int send_tcp_http_request(int fd, char *host, char *ws, int locport);
int send_tcp_http_probe(int fd, char *host, int locport);

int send_tcp_dns_request(int fd, char *host, char *ws, int locport);
int send_udp_dns_request(int fd, char *host, char *ws, int locport);

int send_tcp_dns_probe(int fd, char *host, char *ws, int locport);
int send_udp_dns_probe(int fd, char *host, char *ws, int locport);

int send_udp_ntp_request(int fd, char *host, int locport);
int send_tcp_ntp_request(int fd, char *host, int locport);

int send_udp_ntp_probe(int fd, char *host, int locport);
int send_tcp_ntp_probe(int fd, char *host, int locport);

int send_quic_http_request(int fd, char *host, char *sni, int locport, int ecn);
int send_quic_http_probe(int fd, char *host, char *sni, int locport, int ecn);

#endif