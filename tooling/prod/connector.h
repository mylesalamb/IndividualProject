#ifndef CONNECTOR_H
#define CONNECTOR_H 1

int send_tcp_http_request(char *request, char *host, int locport);
int send_tcp_syn_probe(char *host, int locport);

#endif
