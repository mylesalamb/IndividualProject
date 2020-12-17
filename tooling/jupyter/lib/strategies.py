from lib.parsers import *
from scapy.all import *

@add_metric(TCPConnectonParser)
def is_ecn_negotiated_tcp(packets, ctx) -> bool:
    return False

@add_metric(Parser)
def is_host_reachable(packets, ctx) -> bool:
    for pkt in packets:
        if IP in pkt and pkt[IP].src == ctx.host:
            return True
        if IPv6 in pkt and pkt[IPv6].src == ctx.host:
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
    for pkt in packets:
        if ICMP in pkt and pkt[IP].tos & 0x03:
            out_pkt.append(pkt)
        if ICMPv6 in pkt and pkt[IPv6].tc & 0x03:
            out_pkt.append(pkt)
    return out_pkt

'''Return the first node which shows the marks as missing'''
@add_metric(UDPProbeParser)
def is_ect_stripped(packets, ctx) -> str:
    
    out_pkt = []
    icmp_pkts = filter(lambda x: ICMP in x or ICMPv6 in x, packets)
    for i, pkt in enumerate(icmp_pkts):
        if IPerror in pkt and not (pkt[IPerror].tos & 0x03) :
            (i,icmp_pkts)
        if IPerror6 in pkt and not (pkt[IPerror6].tc & 0x03):
            (i,icmp_pkts)
    return (0,[])

@add_metric(QuicConnectionParser)
def is_ecn_negotiated_quic(packets, ctx) -> bool:
    return False