#ifndef CONTEXT_H
#define CONTEXT_H 1

#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>

// pair together the socket type and the protocol so that driver can create bound
// sockets to pass to the firwalling component
struct sock_conf_t
{
	int sock_type, sock_protocol;
};

// Make ordering clear because we use these in jump tables
enum conn_proto
{
	TCP = 0,
	NTP_UDP = 1,
	NTP_TCP = 2,
	DNS_UDP = 3,
	DNS_TCP = 4,
	QUIC = 5,
	TCP_PROBE = 6,
	NTP_UDP_PROBE = 7,
	NTP_TCP_PROBE = 8,
	DNS_UDP_PROBE = 9,
	DNS_TCP_PROBE = 10,
	QUIC_PROBE = 11
};

// Arguements for constructing different types of sockets
// this does break some abstractions from connector.c
// but allows us to 'un-tether' from a specific port
static struct sock_conf_t socket_conf[] = {
	{SOCK_STREAM, 0},
	{SOCK_DGRAM, 0},
	{SOCK_STREAM, 0},
	{SOCK_DGRAM, 0},
	{SOCK_STREAM, 0},
	{SOCK_DGRAM, 0},

	{SOCK_STREAM, 0},
	{SOCK_DGRAM, 0},
	{SOCK_STREAM, 0},
	{SOCK_DGRAM, 0},
	{SOCK_STREAM, 0},
	{SOCK_DGRAM, 0},

};
// flags for additional fields
// TCP has slightly more complex interactions with
// the network so we can poke and prod to see if anything interesting happens
#define TCP_PROBE_PATH (1 << 0)
#define TCP_HOST_DOWN (1 << 1)
#define TCP_MARK_CONTROL (1 << 2)

struct quic_pkt_t
{
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	uint8_t *pkt_relay;
	ssize_t pkt_relay_len;
};

struct tcp_conn_t
{
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	uint32_t tcp_seq;
	uint32_t tcp_ack;
};

struct connection_context_t
{
	char *host;
	enum conn_proto proto;
	int port;

	// addtional flags for managing connection at runtime
	uint8_t flags;
	uint8_t additional;

	// hacky optimisation for quic probes
	struct quic_pkt_t quic_conn;

	// for probing tcp path mid-connection
	struct tcp_conn_t tcp_conn;
};

void get_context_str(struct connection_context_t *ctx, char *dst);

int ip_ver_str(char *host);

#endif
