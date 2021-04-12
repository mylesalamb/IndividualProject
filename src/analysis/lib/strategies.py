from lib.parsers import *
from scapy.all import *
import pprint

from lib.whois import WhoIs

import shlex
from subprocess import Popen, PIPE

TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ECE = 0x40
TCP_ACK = 0x10
TCP_CWR = 0x80


def _negotiated_ecn_tcp(tcphdr):
    return tcphdr.flags & TCP_SYN and tcphdr.flags & TCP_ECE and tcphdr.flags & TCP_ACK

def _is_icmp_ttl_exceed(icmp):
    return icmp.type == 11 and icmp.code == 0

def has_tcp_ecn_flags(tcphdr):
    return tcphdr.flags & (TCP_SYN | TCP_ECE | TCP_CWR)

def _is_from_host(pkt, ctx):
    return IP in pkt and pkt[IP].src == ctx.host or IPv6 in pkt and pkt[IPv6].src == ctx.host


def _is_to_host(pkt, ctx):
    return (IP in pkt and pkt[IP].dst == ctx.host) or (IPv6 in pkt and pkt[IPv6].dst == ctx.host)

def _is_tcp_rst(tcphdr):
    return True if tcphdr.flags & TCP_RST else False

def get_packet_ttl(pkt):
    if IP in pkt:
        return pkt[IP].ttl
    elif IPv6 in pkt:
        return pkt[IPv6].hlim

@add_metric(TCPConnectonParser)
@add_metric(TCPProbeParser)
def is_ecn_negotiated_tcp(packets, ctx) -> bool:
    for pkt in packets:
        if _is_from_host(pkt, ctx) and TCP in pkt:
            tcp = pkt[TCP]
            if _negotiated_ecn_tcp(tcp):
                return True
    return False

@add_metric(Parser)
def is_host_reachable(packets, ctx) -> bool:
    for pkt in packets:
        if _is_from_host(pkt, ctx):
            return True
    return False


@add_metric(ProbeParser)
def marked_icmp(packets, ctx) -> bool:
    '''
    Pick out ect marked icmp responses
    this was noticed early in the project
    and doesnt seem to be covered in existing research
    '''
    out_pkt = []
    
    for i,pkt in enumerate(packets):
        if ICMP in pkt and pkt[IP].tos & 0x03:
            out_pkt.append([i, pkt[IP].tos])
        if ICMPv6TimeExceeded in pkt and pkt[IPv6].tc & 0x03:
            out_pkt.append([i, pkt[IPv6].tc])
    return out_pkt

'''
    Returns
    The number of hops until the ect markings disappear
    The number of hops to the host (max ttl before response)
    The index into the packets list containing the first icmp without ect markings
    list of items (corresponding hop, network interface)
'''
@add_metric(UDPProbeParser)
@add_metric(TCPConnectonParser)
@add_metric(QuicProbeParser)
@add_metric(TCPProbeParser)
def is_ect_stripped(packets, ctx) -> str:

    whois = WhoIs.instance()
    as_data = []
    icmp_data = []

    
    if ctx.flags == 0:
        return [-1,-1,-1]

    hops = 1

    hops_before_removal = -1
    removal_index = -1
    hops_before_host = -1
    icmp_index = -1

    likely_src = None

    for i, pkt in enumerate(packets):

        if _is_to_host(pkt,ctx) and not likely_src:
            if IPv6 in pkt:
                likely_src = pkt[IPv6].src
            elif IP in pkt:
                likely_src = pkt[IP].src
        

        #if pkt from host, set the hops value, also prevent registering pkts sent from
        if _is_to_host(pkt, ctx) and get_packet_ttl(pkt) < 60:
            hops = get_packet_ttl(pkt)

        if ICMP in pkt and _is_icmp_ttl_exceed(pkt[ICMP]):

            as_datum = whois.lookup(pkt[IP].src)
            icmp_data.append((hops, pkt[IP].src, pkt[IPerror].tos))

            if IPerror in pkt and not (pkt[IPerror].tos & 0x03):
            
                if as_datum:
                    as_data.append(as_datum)
                if hops_before_removal == -1:
                    hops_before_removal = hops
                    removal_index = i
            
            
        # ICMP response somewhere on the path
        if ICMPv6TimeExceeded in pkt and IPerror6 in pkt:
            
            icmp_data.append((hops, pkt[IPv6].src, pkt[IPerror6].tc))
            as_datum = whois.lookup(pkt[IPv6].src)
            
            # has the ect marking been removed
            if not (pkt[IPerror6].tc & 0x03) and hops_before_removal == -1:
                if as_datum:
                    as_data.append(as_datum)
                hops_before_removal = hops
                removal_index = i
            

        if _is_from_host(pkt, ctx) and hops > 5:
            hops_before_host = hops
            break
    
    

    return (hops_before_removal, removal_index, hops_before_host, icmp_data)

@add_metric(TCPProbeParser)
def is_syn_ecn_stripped(packets, ctx):

    if ctx.flags == 0:
        return ()

    hops = 1

    hops_before_removal = -1
    removal_index = -1
    hops_before_host = -1

    for i, pkt in enumerate(packets):
        
        #if pkt from host, set the hops value
        if _is_to_host(pkt, ctx):
            hops = get_packet_ttl(pkt)

        if TCPerror in pkt and (pkt[TCPerror].flags & TCP_SYN) and not has_tcp_ecn_flags(pkt[TCPerror]) and hops_before_removal == -1:
            hops_before_removal = hops
            removal_index = i
            break
        
        if _is_from_host(pkt, ctx):
            hops_before_host = hops
            break
            
    return (hops_before_removal, removal_index, hops_before_host)

@add_metric(TCPProbeParser)
def does_host_reset(packets, ctx):

    for i, pkt in enumerate(packets):
        if _is_from_host(pkt,ctx) and TCP in pkt:
            if _is_tcp_rst(pkt[TCP]):
                return i
            else:
                break
    
    return -1
    
# Exec a tshark proc to get the information and just parse whatever comes out
# All we are looking for is either, the host to mark responses, or, to respond with an ECN ack frame
# Which we filter for here
@add_metric(QuicConnectionParser)
def is_ecn_negotiated_quic(packets, ctx) -> bool:

    # get the keys file for the connection, and filter on ecn ack frames to see if we get any text back
    keyfile=f"{os.path.dirname(ctx.file_loc)}/keystore/{ctx.host}-{format(ctx.flags, '02x')}.keys"
    filter_pkt = "quic.ack.ecn_ce_count || quic.ack.ect0_count || quic.ack.ect0_count"
    cmd=f"tshark -r {ctx.file_loc} -j \"http udp\" -o tls.keylog_file:{keyfile} -Y \"{filter_pkt}\""
    
    proc = Popen(shlex.split(cmd), stdout=PIPE)
    (stdout, stderr) = proc.communicate()
    exit_code = proc.wait()

    if exit_code:
        print("Tshark exited abnormally!")
    elif stdout:
        return True

        
    return False


