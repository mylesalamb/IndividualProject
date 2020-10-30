#ifndef CONNECTOR_H
#define CONNECTOR_H 1

int send_tcp_http_request(char *request, char *host, int locport);
int send_tcp_syn_probe(char *host, int locport);

int send_udp_ntp_request(char *host, int locport);
int send_udp_ntp_probe(char *host, int locport);

int send_udp_dns_request(char *resolver, char *host);

#endif
