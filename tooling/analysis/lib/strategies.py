from lib.parsers import *
from scapy.all import *
import pprint

import shlex
from subprocess import Popen, PIPE

TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ECE = 0x40
TCP_ACK = 0x10


def _negotiated_ecn_tcp(tcphdr):
    return tcphdr.flags & TCP_SYN and tcphdr.flags & TCP_ECE and tcphdr.flags & TCP_ACK

def _is_from_host(pkt, ctx):
    return IP in pkt and pkt[IP].src == ctx.host or IPv6 in pkt and pkt[IPv6].src == ctx.host


def _is_to_host(pkt, ctx):
    return IP in pkt and pkt[IP].dst == ctx.host or IPv6 in pkt and pkt[IPv6].dst == ctx.host

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

@add_metric(TCPConnectonParser)
def is_ect_stripped_tcp(packets, ctx):
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
            out_pkt.append(i)
        if ICMPv6TimeExceeded in pkt and pkt[IPv6].tc & 0x03:
            out_pkt.append(i)
    return out_pkt

'''
    Returns
    The number of hops until the ect markings disappear
    The number of hops to the host (max ttl before response)
    The index into the packets list containing the first icmp without ect markings
'''
@add_metric(UDPProbeParser)
@add_metric(TCPConnectonParser)
@add_metric(QuicProbeParser)
def is_ect_stripped(packets, ctx) -> str:
    
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

        if ICMP in pkt and IPerror in pkt and not (pkt[IPerror].tos & 0x03) and hops_before_removal == -1:
            hops_before_removal = hops
            removal_index = i
        
        # ICMP response somewhere on the path
        if ICMPv6TimeExceeded in pkt and IPerror6 in pkt and not (pkt[IPerror6].tc & 0x03) and hops_before_removal == -1:
            hops_before_removal = hops
            removal_index = i

        if _is_from_host(pkt, ctx):
            hops_before_host = hops
            break
            
    return (hops_before_removal, removal_index, hops_before_host)

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

        if TCPerror in pkt and not (pkt[IPerror].tos & 0x03) and hops_before_removal == -1:
            hops_before_removal = hops
            removal_index = i
        
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


