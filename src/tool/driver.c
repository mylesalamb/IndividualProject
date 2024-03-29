#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <errno.h>

#include "connector.h"
#include "context.h"
#include "log.h"
#include "netinject.h"
#include "parser.h"
#include "pcapture.h"

#include "lsquic.h"

// pseudo user to tidy up firewalling
#define USER "ecnDetector_psuedo"

static void print_usage();

static int set_user();

static int dispatch_web(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc);
static int dispatch_dns(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc);
static int dispatch_ntp(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc);

static int (*transac_disaptch[])(struct transaction_node_t *transac,
                                 struct nf_controller_t *nfc,
                                 struct pcap_controller_t *pc) = {
    &dispatch_web, &dispatch_dns, &dispatch_ntp};

char *alias = NULL;
char *infile = NULL;
char *outdir = "data";
char arg;

int main(int argc, char **argv)
{

// memory sanitizers have a hard tme with this
#ifndef DEBUG
  set_user();
#endif

  log_init();

  while ((arg = getopt(argc, argv, "a:f:d:hv")) != -1)
  {
    switch (arg)
    {
    case 'a':
      alias = optarg;
      break;

    case 'f':
      infile = optarg;
      break;
    case 'd':
      outdir = optarg;
      break;
    case 'h':
      print_usage();
      return EXIT_SUCCESS;
      break;
    case '?':
      print_usage();
      return EXIT_FAILURE;
      break;
    }
  }

  if (!infile)
  {
    LOG_ERR("must provide input file\n");
    return EXIT_FAILURE;
  }

  if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
  {
    LOG_ERR("lsquic global init\n");
    exit(EXIT_FAILURE);
  }

  struct transaction_list_t *transactions = fget_transactions(infile);
  if (!transactions)
  {
    LOG_ERR("infile parse error\n");
    return EXIT_FAILURE;
  }

  struct pcap_controller_t *pc = pcap_init(alias, outdir);
  struct nf_controller_t *nf = nf_init();

  // dispatch the head of each transac list
  for (int i = 0; i < _COUNT; i++)
  {

    struct transaction_node_t *transac = transactions->type_headers[i];
    if (!transac)
      continue;
    transac_disaptch[transac->type](transac, nf, pc);
  }

  pcap_free(pc);
  nf_free(nf);
  lsquic_global_cleanup();

  transaction_list_free(transactions);

  LOG_INFO("Complete\n");
  return EXIT_SUCCESS;
}

// call the underlying singular dispatch function
// for each transac, suitable for web and dns
// not ntp
static int
dispatch_for_each(struct transaction_node_t *transacs,
                  struct nf_controller_t *nfc, struct pcap_controller_t *pc,
                  int(dispatch_single)(struct transaction_node_t *transac,
                                       struct nf_controller_t *nfc,
                                       struct pcap_controller_t *pc))
{

  struct transaction_node_t *cursor = transacs;

  while (cursor)
  {
    dispatch_single(cursor, nfc, pc);
    cursor = cursor->next;
  }
  return 0;
}

static int dispatch_web_singular(struct transaction_node_t *transac,
                                 struct nf_controller_t *nfc,
                                 struct pcap_controller_t *pc)
{
  LOG_INFO("dispatch web, to host %s\n", transac->ctx->host);
  int ecn;
  transac->ctx->proto = TCP;
  for (ecn = 0; ecn < 4; ecn++)
  {
    int fd, ret;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);

    transac->ctx->flags = ecn;
    transac->ctx->additional |= ecn ? TCP_PROBE_PATH : 0;

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    ret = send_tcp_http_request(fd, transac->ctx->host, transac->request,
                                transac->ctx->port, ecn, &transac->ctx->tcp_conn);

    pcap_close_context(pc);
    nf_close_context(nfc);
    transac->ctx->tcp_conn.tcp_seq = 0;
    transac->ctx->tcp_conn.tcp_ack = 0;

    if (ret && ecn == 0)
    {
      LOG_INFO("TCP host likely down skipping\n");
      break;
    }
  }
  transac->ctx->additional = 0;

  transac->ctx->proto = QUIC;
  for (ecn = 0; ecn < 4; ecn++)
  {
    transac->ctx->flags = ecn;

    int fd, ret;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    ret = send_quic_http_request(fd, transac->ctx->host, transac->request,
                                 transac->ctx->port, ecn, outdir);
    pcap_close_context(pc);
    nf_close_context(nfc);
    if (ret && ecn == 0)
    {
      LOG_INFO("Quic host likely down\n");
      break;
    }
  }

  transac->ctx->proto = TCP_PROBE;
  transac->ctx->additional |= TCP_MARK_CONTROL;
  for (uint8_t ecn = 0; ecn < 3; ecn++)
  {
    transac->ctx->flags = ecn;

    int fd;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    send_tcp_http_probe(fd, transac->ctx->host, transac->ctx->port);
    pcap_close_context(pc);
    nf_close_context(nfc);
  }
  transac->ctx->additional &= ~TCP_MARK_CONTROL;

  transac->ctx->proto = QUIC_PROBE;
  for (ecn = 0; ecn < 4; ecn++)
  {
    transac->ctx->flags = ecn;

    int fd, ret;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    ret = send_quic_http_probe(fd, transac->ctx->host, transac->request, transac->ctx->port,
                               ecn, &transac->ctx->quic_conn);

    pcap_close_context(pc);
    nf_close_context(nfc);
    free(transac->ctx->quic_conn.pkt_relay);
    transac->ctx->quic_conn.pkt_relay = NULL;
    transac->ctx->quic_conn.pkt_relay_len = 0;
    
    if (ret && ecn == 0)
    {
      LOG_INFO("Host likely down, skipping\n");
      break;
    }
  }

  return 0;
}

static int dispatch_web(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc)
{
  dispatch_for_each(transac, nfc, pc, &dispatch_web_singular);
  return 0;
}

static int dispatch_dns_singular(struct transaction_node_t *transac,
                                 struct nf_controller_t *nfc,
                                 struct pcap_controller_t *pc)
{
  LOG_INFO("dispatch dns, to host %s\n", transac->ctx->host);
  int ecn;

  transac->ctx->proto = DNS_TCP;
  for (ecn = 0; ecn < 4; ecn++)
  {
    int fd, ret;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);

    transac->ctx->flags = ecn;
    transac->ctx->additional |= ecn ? TCP_PROBE_PATH : 0;

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    ret = send_tcp_dns_request(fd, transac->ctx->host, transac->request,
                               transac->ctx->port, ecn, &transac->ctx->tcp_conn);

    pcap_close_context(pc);
    nf_close_context(nfc);
    transac->ctx->tcp_conn.tcp_seq = 0;
    transac->ctx->tcp_conn.tcp_ack = 0;
    if (ret && ecn == 0)
    {
      LOG_INFO("Host likely down, skipping\n");
      break;
    }
  }

  transac->ctx->proto = DNS_UDP;
  for (ecn = 0; ecn < 4; ecn++)
  {

    int fd;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);

    transac->ctx->flags = ecn;

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    send_udp_dns_request(fd, transac->ctx->host, transac->request,
                         transac->ctx->port);

    pcap_close_context(pc);
    nf_close_context(nfc);
  }

  transac->ctx->proto = DNS_UDP_PROBE;
  for (uint8_t ecn = 0; ecn < 4; ecn++)
  {

    int fd;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);
    LOG_INFO("dns port is %d\n", transac->ctx->port);

    transac->ctx->flags = ecn;

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    send_udp_dns_probe(fd, transac->ctx->host, transac->request,
                       transac->ctx->port);
    pcap_close_context(pc);
    nf_close_context(nfc);
  }

  transac->ctx->proto = DNS_TCP_PROBE;
  transac->ctx->additional |= TCP_MARK_CONTROL;
  for (ecn = 0; ecn < 3; ecn++)
  {
    transac->ctx->flags = ecn;

    int fd;
    init_conn(transac->ctx->host, transac->ctx->proto, &fd, &transac->ctx->port);

    pcap_push_context(pc, transac->ctx);
    pcap_wait_until_rdy(pc);

    nf_push_context(nfc, transac->ctx);
    nf_wait_until_rdy(nfc);

    send_tcp_dns_probe(fd, transac->ctx->host, transac->request,
                       transac->ctx->port);

    pcap_close_context(pc);
    nf_close_context(nfc);
  }
  transac->ctx->additional &= ~TCP_MARK_CONTROL;

  return 0;
}

static int dispatch_dns(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc)
{
  dispatch_for_each(transac, nfc, pc, &dispatch_dns_singular);
  return 0;
}

// TODO refactor to do stuff properly
static int dispatch_ntp(struct transaction_node_t *transac,
                        struct nf_controller_t *nfc,
                        struct pcap_controller_t *pc)
{
  LOG_INFO("dispatch ntp, to host %s\n", transac->ctx->host);
  uint8_t ecn;

  for (ecn = 0; ecn < 4; ecn++)
  {

    struct transaction_node_t *cursor = transac;
    while (cursor)
    {
      cursor->ctx->proto = NTP_TCP;

      int fd;
      int ret = 0;

      if (!(cursor->ctx->additional & TCP_HOST_DOWN))
      {
        init_conn(cursor->ctx->host, cursor->ctx->proto, &fd, &cursor->ctx->port);
        cursor->ctx->flags = ecn;
        cursor->ctx->additional |= ecn ? TCP_PROBE_PATH : 0;

        pcap_push_context(pc, cursor->ctx);
        pcap_wait_until_rdy(pc);

        nf_push_context(nfc, cursor->ctx);
        nf_wait_until_rdy(nfc);

        ret = send_tcp_ntp_request(fd, cursor->ctx->host, cursor->ctx->port, ecn, &cursor->ctx->tcp_conn);

        pcap_close_context(pc);
        nf_close_context(nfc);
      }
      
      cursor->ctx->tcp_conn.tcp_seq = 0;
      cursor->ctx->tcp_conn.tcp_ack = 0;
      cursor->ctx->additional &= ~TCP_PROBE_PATH;
      if (ret && ecn == 0)
      {
        cursor->ctx->additional |= TCP_HOST_DOWN;
      }
      cursor = cursor->next;
    }
  }

  for (ecn = 0; ecn < 4; ecn++)
  {

    struct transaction_node_t *cursor = transac;
    while (cursor)
    {

      cursor->ctx->proto = NTP_UDP;

      int fd;
      init_conn(cursor->ctx->host, cursor->ctx->proto, &fd, &cursor->ctx->port);

      cursor->ctx->flags = ecn;

      pcap_push_context(pc, cursor->ctx);
      pcap_wait_until_rdy(pc);

      nf_push_context(nfc, cursor->ctx);
      nf_wait_until_rdy(nfc);

      send_udp_ntp_request(fd, cursor->ctx->host, cursor->ctx->port);

      pcap_close_context(pc);
      nf_close_context(nfc);
      cursor = cursor->next;
    }
  }

  for (ecn = 0; ecn < 4; ecn++)
  {
    struct transaction_node_t *cursor = transac;
    while (cursor)
    {
      cursor->ctx->proto = NTP_UDP_PROBE;
      cursor->ctx->flags = ecn;

      int fd;
      init_conn(cursor->ctx->host, cursor->ctx->proto, &fd, &cursor->ctx->port);

      pcap_push_context(pc, cursor->ctx);
      pcap_wait_until_rdy(pc);

      nf_push_context(nfc, cursor->ctx);
      nf_wait_until_rdy(nfc);

      send_udp_ntp_probe(fd, cursor->ctx->host, cursor->ctx->port);
      pcap_close_context(pc);
      nf_close_context(nfc);
      cursor = cursor->next;
    }
  }

  for (ecn = 0; ecn < 3; ecn++)
  {

    struct transaction_node_t *cursor = transac;
    while (cursor)
    {

      cursor->ctx->flags = ecn;
      cursor->ctx->proto = NTP_TCP_PROBE;
      cursor->ctx->additional |= TCP_MARK_CONTROL;

      int fd;
      init_conn(cursor->ctx->host, cursor->ctx->proto, &fd, &cursor->ctx->port);

      pcap_push_context(pc, cursor->ctx);
      pcap_wait_until_rdy(pc);

      nf_push_context(nfc, cursor->ctx);
      nf_wait_until_rdy(nfc);

      send_tcp_ntp_probe(fd, cursor->ctx->host, cursor->ctx->port);

      pcap_close_context(pc);
      nf_close_context(nfc);
      cursor->ctx->additional &= ~TCP_MARK_CONTROL;
      cursor = cursor->next;
    }
  }

  return 0;
}

static void print_usage()
{

  printf("ECN Detector usage:\n"
         "\t-a alias to prefix to outputted file names\n"
         "\t-f input file name containing transactions to carry out\n"
         "\t-d output directory name\n");
}

// Set the uid of the process
static int set_user()
{
  struct passwd *pwd = getpwnam(USER);
  if (!pwd)
  {
    LOG_ERR("getpwnam failed\n");
    return -1;
  }

  if (setgid(pwd->pw_gid) != 0)
  {
    LOG_ERR("setgid failed, check capabilities\n");
    return -1;
  }

  if (setuid(pwd->pw_uid) != 0)
  {
    LOG_ERR("setuid failed, check capabilities\n");
    return -1;
  }

  return 0;
}
