#ifndef CONNECTOR_H
#define CONNECTOR_H 1


int send_tcp_http_request(char *host, char *ws, int locport);
int send_tcp_http_probe(char *host, int locport);

int send_tcp_dns_request(char *host, char *ws, int locport);
int send_udp_dns_request(char *host, char *ws, int locport);

int send_tcp_dns_probe(char *host, char *ws, int locport);
int send_udp_dns_probe(char *host, char *ws, int locport);

int send_udp_ntp_request(char *host, int locport);
int send_tcp_ntp_request(char *host, int locport);

int send_udp_ntp_probe(char *host, int locport);
int send_tcp_ntp_probe(char *host, int locport);

int send_quic_http_request(char *host, char *sni, int locport, int ecn);

#endif