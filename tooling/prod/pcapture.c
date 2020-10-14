#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>

int pcap_debug()
{
    char *device;
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw;
    bpf_u_int32 subnet_mask_raw;
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct in_addr address;

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("%s\n", error_buffer);
        return 1;
    }
    
    /* Get device info */
    lookup_return_code = pcap_lookupnet(
        device,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

    /* Get ip in human readable form */
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* print error */
        return 1;
    }
    
    /* Get subnet mask in human readable form */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }

    printf("Device: %s\n", device);
    printf("IP address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);

    return 0;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void pcap_log_conn(char *host, int port)
{
    char outfile[32];
    sprintf(outfile, "%s-%d.pcap", host, port);
    pcap_dumper_t *pd;
    char dev[] = "enp3s0";
    char filter_exp[32];
    sprintf(filter_exp, "port %d or dst port %d", port, port);
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return;
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return;
    }

    packet = pcap_next(handle, &packet_header);
     if (packet == NULL) {
        printf("No packet found.\n");
        return;
    }

    // should be replaced with pcap dispatch ordeal
    pd = pcap_dump_open(handle, outfile);
    pcap_dump(pd, &packet_header,packet);
    pcap_dump_close(pd);

    // until connection signalled over
    // connector has read responses
    // spin

    //then return

    /* Our function to output some info */
    print_packet_info(packet, packet_header);
    pcap_close(handle);
}