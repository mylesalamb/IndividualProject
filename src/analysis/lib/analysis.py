import pprint
from graphviz import Graph
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import numpy as np
import geoip2.database
import json
import redis
import lib.whois
from collections import defaultdict

# connection to offline redis cache of AS numbers harvested during initial parse of data
REDIS_HOST = "localhost"
REDIS_PORT = 6379
connection = redis.Redis(REDIS_HOST, port=REDIS_PORT)


# need to add ntp ecn negotiation on probes

def compute_reachability_stats_udp_ntp(instances):
    
    results = {}

    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            ntp_hosts = []
            ntp_reach = [0,0,0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "ntp_udp", datum)):
                    print(host)
                    ntp_hosts.append((host, datum))

            for host, data in ntp_hosts:
                for stat in data:
                    if stat["proto"] == "ntp_udp":
                        if stat["is_host_reachable"]:
                            ntp_reach[stat["flags"]] += 1
            results[name].append(ntp_reach)

    return results

def compute_cdf_tcp_ect(instances):
    datums_raw = []

    for instance in instances:
        for trace in instance["data"]:
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "tcp", datum)):
                    datums_raw.append(datum)
    
    # Now we should have all the webhosts in datums_raw
    # Apply some filters, removing, down hosts, and hosts that do not strip ect markings

    def filter_up_and_flagged(x):
        for entry in x:
            if entry["proto"] == "tcp" and entry["flags"] and entry["is_ect_stripped"][0] != -1:
                return True
        return False


    datums_up = list(filter(filter_up_and_flagged, datums_raw))

    print("### datums up ###")

    
    # Values values dependant on markings
    # Plot deperately
    ect = [[],[],[]]
    ect_color = ["#332288", "#88CCEE", "#44AA99"]
    
    for datum in datums_up:
        for entry in datum:
            if entry["proto"] == "tcp" and entry["flags"] and entry["is_ect_stripped"][0] != -1:
                strip = entry["is_ect_stripped"]
                ect[entry["flags"] - 1].append(strip[0] / strip[2])

    pprint.pprint(ect)
    # plot the sorted data:
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.set_title("CDF representing where ECT codepoints are cleared\nfor Webserver hosts (TCP)")
    ax1.set_xlabel('interface hop divided by number of interface hops on path')
    ax1.set_ylabel('Fraction')

    plots = []

    for i, data in enumerate(ect):

        # sort the data:
        data_sorted = np.sort(data)
        data_sorted = data_sorted[data_sorted >= 0]
        pprint.pprint(data_sorted)

        # calculate the proportional values of samples
        p = 1. * np.arange(len(data_sorted)) / (len(data_sorted) - 1)

        ax1.plot(data_sorted, p, color=ect_color[i], alpha=0.7)
        
        plots.append(mpatches.Patch(color=ect_color[i], label=f'ECT({i}) traces'))
    plt.legend(handles=plots)
        
    plt.xlim([0, 1])
    plt.ylim([0, 1])

    fig.savefig(f"tcp_ect.svg")

# Only 4,5 DC
def compute_cdf_quic_ect(instances):
    datums_raw = []

    for instance in instances:
        for trace in instance["data"]:
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "quic_probe", datum)):
                    datums_raw.append(datum)
    
    # Now we should have all the webhosts in datums_raw
    # Apply some filters, removing, down hosts, and hosts that do not strip ect markings

    def filter_up_and_flagged(x):
        for entry in x:
            if entry["proto"] == "quic_probe" and entry["flags"] and entry["is_ect_stripped"][0] != -1:
                return True
        return False


    datums_up = list(filter(filter_up_and_flagged, datums_raw))

    print("### datums up ###")

    
    # Values values dependant on markings
    # Plot deperately
    ect = [[],[],[]]
    ect_color = ["#332288", "#88CCEE", "#44AA99"]
    
    for datum in datums_up:
        for entry in datum:
            if entry["proto"] == "quic_probe" and entry["flags"] and entry["is_ect_stripped"][0] != -1:
                strip = entry["is_ect_stripped"]
                ect[entry["flags"] - 1].append(strip[0] / strip[2])

    pprint.pprint(ect)
    # plot the sorted data:
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.set_title("CDF representing where ECT codepoints are cleared\nfor Webserver hosts (Quic)")
    ax1.set_xlabel('interface hop divided by number of interface hops on path')
    ax1.set_ylabel('Fraction')

    plots = []

    for i, data in enumerate(ect):

        # sort the data:
        data_sorted = np.sort(data)
        data_sorted = data_sorted[data_sorted >= 0]
        pprint.pprint(data_sorted)

        # calculate the proportional values of samples
        p = np.arange(len(data_sorted)) / (len(data_sorted))

        ax1.plot(data_sorted, p, color=ect_color[i], alpha=0.7)
        # ax1.hist(data_sorted, cumulative=True, label='CDF',
        #  histtype='step', alpha=0.8, color='k')
        
        plots.append(mpatches.Patch(color=ect_color[i], label=f'ECT({i}) traces'))
    plt.legend(handles=plots)
        
    plt.xlim([0, 1])
    plt.ylim([0, 1])

    fig.savefig(f"quic_ect.svg")

def compute_basic_strip_stats_tcp_web(instances):
    results = {}

    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            ntp_hosts = []
            ntp_reach = [0,0,0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "tcp", datum)):
                    ntp_hosts.append((host, datum))

            for host, data in ntp_hosts:
                for stat in data:
                    if stat["proto"] == "tcp":
                        if stat["is_ect_stripped"][0] != -1:
                            print(f"stripped on: {host}")
                            ntp_reach[stat["flags"]] += 1
            results[name].append(ntp_reach)
    return results

def compute_basic_strip_stats_tcp_web_probe(instances):
    results = {}

    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            ntp_hosts = []
            ntp_reach = [0,0,0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "tcp_probe", datum)):
                    ntp_hosts.append((host, datum))

            for host, data in ntp_hosts:
                for stat in data:
                    if stat["proto"] == "tcp_probe":
                        if stat["is_ect_stripped"][0] != -1:
                            print(f"stripped on: {host}")
                            ntp_reach[stat["flags"]] += 1
            results[name].append(ntp_reach)

    return results


def compute_basic_strip_stats_udp_ntp(instances):

    results = {}

    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            ntp_hosts = []
            ntp_reach = [0,0,0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "ntp_udp_probe", datum)):
                    ntp_hosts.append((host, datum))

            for host, data in ntp_hosts:
                for stat in data:
                    if stat["proto"] == "ntp_udp_probe":
                        if stat["is_ect_stripped"][0] != -1:
                            print(f"stripped on: {host}")
                            ntp_reach[stat["flags"]] += 1
            results[name].append(ntp_reach)

    return results

def compute_basic_ecn_negotation_stats(instances):
    results = {}
    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            web_hosts = []
            dns_hosts = []
            ntp_hosts = []
            ecn_negotiated_web = {"ipv4": [0,0], "ipv6": [0,0]}
            ecn_negotiated_dns = {"ipv4": [0,0], "ipv6": [0,0]}
            ecn_negotiated_ntp = {"ipv4": [0,0], "ipv6": [0,0]}

            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "tcp", datum)):
                    web_hosts.append((host, datum))
                if any(map(lambda x: x["proto"] == "dns_tcp", datum)):
                    dns_hosts.append((host, datum))
                if any(map(lambda x: x["proto"] == "ntp_tcp_probe", datum)):
                    ntp_hosts.append((host, datum))



            for host, data in web_hosts:
                host_ver = "ipv6" if ":" in host else "ipv4"
                for stat in data:
                    if stat["proto"] == "tcp" and stat["flags"] == 2:
                        if not stat["is_host_reachable"]:
                            continue
                        if stat["is_ecn_negotiated_tcp"]:
                            ecn_negotiated_web[host_ver][1] += 1
                        else:
                            ecn_negotiated_web[host_ver][0] += 1

            for host, data in dns_hosts:
                host_ver = "ipv6" if ":" in host else "ipv4"
                for stat in data:
                    if stat["proto"] == "dns_tcp" and stat["flags"] == 2:
                        if not stat["is_host_reachable"]:
                            continue
                        if stat["is_ecn_negotiated_tcp"]:
                            ecn_negotiated_dns[host_ver][1] += 1
                        else:
                            ecn_negotiated_dns[host_ver][0] += 1

            for host, data in ntp_hosts:
                host_ver = "ipv6" if ":" in host else "ipv4"
                for stat in data:
                    if stat["proto"] == "ntp_tcp_probe" and stat["flags"] == 2:
                        if not stat["is_host_reachable"]:
                            continue
                        if stat["is_ecn_negotiated_tcp"]:
                            ecn_negotiated_ntp[host_ver][1] += 1
                        else:
                            ecn_negotiated_ntp[host_ver][0] += 1



            results[name].append({"web": ecn_negotiated_web, "dns": ecn_negotiated_dns, "ntp": ecn_negotiated_ntp})

    return results


def compute_ecn_negotiation_quic(instances):
    results = {}
    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for i,trace in enumerate(instance["data"]):
            web_hosts = []
            ecn_negotatiated = [0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "quic", datum)):
                    web_hosts.append((host, datum))

            for host, data in web_hosts:
                for stat in data:
                    if stat["proto"] == "quic" and stat["flags"] == 1:
                        if stat["is_ecn_negotiated_quic"]:
                            print(f"{host} NEGOTIATED QUIC, with trace {i}")
                            ecn_negotatiated[1] += 1
                        else:
                            ecn_negotatiated[0] += 1

            results[name].append(ecn_negotatiated)

    return results

import datetime as dt

def generate_ecn_trends_graph(input_file):
    xs = []
    ys = []
    x6s = []
    y6s = []
    authors6 = []
    authors = []

    with open(input_file) as f:
        for line in f:
            author, adoption, date, ip = [ x.strip() for x in line.strip().split(",")]
            if ip == "ip4":
                authors.append(author)
                xs.append(dt.datetime.strptime(date,'%d/%m/%Y').date())
                ys.append(float(adoption))
            else:
                authors6.append(author)
                x6s.append(dt.datetime.strptime(date,'%d/%m/%Y').date())
                y6s.append(float(adoption))

    fig, ax = plt.subplots()
    
    ax.scatter(xs, ys, label="IPv4")
    ax.scatter(x6s, y6s, label="IPv6")
    for i, author in enumerate(authors):
        ax.annotate(author, (xs[i], ys[i]))
    for i, author in enumerate(authors6):
        ax.annotate(author, (x6s[i], y6s[i]))
    ax.legend()
    ax.set_xlabel("Time (year)")
    ax.set_ylabel("Proportions of hosts that negotiated ECN")
    fig.savefig("ecn_trends.pdf")

def ipv4_ipv6_stuff(instances):
    matchings = {}
    hostnames = []
    matched = []
    rev = {}

    with open("aux.web.dataset") as f:
        for line in f:
            ipv4, ipv6, hostname = line.strip().split(",")
            matchings[ipv4] = hostname
            matchings[ipv6] = hostname
            hostnames.append(hostname)
            rev[hostname] = []
            if ipv4:
                rev[hostname].append(ipv4)
            if ipv6:
                rev[hostname].append(ipv6)


    for instance in instances:
        

        for trace in instance["data"]:
            crossref = {x: 0 for x in hostnames}
            for host, datum in trace.items():
                for elt in datum:
                    if elt["proto"] != "tcp_probe":
                        continue
                    if elt["flags"] != 0x02:
                        continue
                    hops_to_host = elt["is_ect_stripped"][2]
                    if not crossref[matchings[host]]:
                        crossref[matchings[host]] = hops_to_host
                    elif crossref[matchings[host]] == hops_to_host:
                        matched.append(matchings[host])

    incl = [item for sublist in  map(lambda x: rev[x], matched) for item in sublist]
    ret = {}

    for instance in instances:
        counts = []
        for trace in instance["data"]:
            count = [0, 0]
            for host, datum in trace.items():
                
                if host not in incl:
                    continue
                
                for elt in datum:
                    if elt["proto"] != "tcp" or elt["flags"] != 0x02:
                        continue

                    if not elt["is_ect_stripped"][0] != -1:
                        continue

                    if ":" in host:
                        count[1] += 1
                    else:
                        count[0] += 1
            counts.append(count)
        ret[instance["name"]] = counts

    final = []

    for key, item in ret.items():
        
        count4, count6 = 0, 0
        for ipv4, ipv6 in item:
            count4 += ipv4
            count6 += ipv6
        
        count4 /= len(item)
        count6 /= len(item)
        final.append((count4, count6))
    print("ipv4/6 stuff")
    pprint.pprint(final)

def find_interfaces(instances):
    pass

def compute_ect_stripped_quic(instances):

    results = {}
    for instance in instances:
        
        name = instance["name"]

        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            web_hosts = []
            ect_stripped = [0,0,0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "quic_probe", datum)):
                    web_hosts.append((host, datum))

            for host, data in web_hosts:
                for stat in data:
                    if stat["proto"] == "quic_probe":
                        if stat["is_ect_stripped"][0] != -1:
                            print(f"quic strip: {host}")
                            ect_stripped[stat["flags"]] += 1
                        

            results[name].append(ect_stripped)

    return results

def compute_tcp_udp_correlation(instances):

    hosts = {}
    trace_counts = {}

    # get dns hosts that operate over both tcp and udp
    for instance in instances:
        hosts[instance["name"]] = []
        trace_counts[instance["name"]] = len(instance["data"])
        for trace in instance["data"]:
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "dns_tcp" and x["is_host_reachable"], datum)) and \
                any(map(lambda x: x["proto"] == "dns_udp" and x["is_host_reachable"], datum)):
                    hosts[instance["name"]].append((host, datum))
    
    
    names = []
    xs = []
    ys = []

    for instance_name, resolvers in hosts.items():
        if "Part" in instance_name and "1" in instance_name:
            continue
        udp_count = 0
        tcp_count = 0
        for host, datum in resolvers:
            pre = False
            for elt in datum[::-1]:
                
                if elt["proto"] == "dns_udp_probe" and elt["flags"] == 2 and elt["is_ect_stripped"][0] != -1:
                    pre = True
                    udp_count +=1
                if elt["proto"] == "dns_tcp_probe" and elt["flags"] == 2 and elt["is_ect_stripped"][0] != -1 and pre:
                    tcp_count += 1

        udp_count /= trace_counts[instance_name]
        tcp_count /= trace_counts[instance_name]
        print("{}: udp:{} tcp:{}".format(instance_name, udp_count, tcp_count))
        names.append(instance_name)
        xs.append(udp_count)
        ys.append(tcp_count)


    print(xs)
    print(ys)
    fig, ax = plt.subplots()
    ax.scatter(xs, ys)
    ax.set_title("Correlation between on path UDP and TCP removal")
    ax.set_xlabel("Number of Paths that experience ECT removal under UDP")
    ax.set_ylabel("Number of paths that also\nexperience ECT removal under TCP")

    fig.savefig("tcpudp.pdf")


def ect_marked_icmp_stats(instances):
    ret = {}

    for instance in instances:
        protos = {}

        if instance["name"] == "ian":
            continue

        for trace in instance["data"]:
            for host, datum in trace.items():
                if ":" in host:
                    continue
                for elt in datum:
                    if "marked_icmp" in elt:
                        val = protos.setdefault(elt["proto"], [0, 0])
                        if elt["marked_icmp"]:
                            val[0] += 1
                        else:
                            val[1] += 1

        ret[instance["name"]] = protos
        pprint.pprint(ret)

        total_y = 0
        total_n = 0

        for instance, vals in ret.items():
            for proto, counts in vals.items():
                if "quic" in proto:
                    continue
                counted, not_counted = counts
                total_y += counted
                total_n += not_counted

        print("total conn with ect marked icmp: {}".format(total_y / (total_y + total_n)))



def compute_tcp_udp_strip_stats(instances):
    
    hosts = {}
    trace_counts = {}

    # get dns hosts that operate over both tcp and udp
    for instance in instances:
        hosts[instance["name"]] = []
        trace_counts[instance["name"]] = len(instance["data"])
        for trace in instance["data"]:
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "dns_tcp" and x["is_host_reachable"], datum)) and \
                any(map(lambda x: x["proto"] == "dns_udp" and x["is_host_reachable"], datum)):
                    hosts[instance["name"]].append((host, datum))
    
    
    for instance_name, resolvers in hosts.items():
        udp_count = 0
        tcp_count = 0
        for host, datum in resolvers:
            for elt in datum:
                if elt["proto"] == "dns_udp_probe" and elt["flags"] == 2 and elt["is_ect_stripped"][0] != -1:
                    udp_count +=1
                
                if elt["proto"] == "dns_tcp_probe" and elt["flags"] == 2 and elt["is_ect_stripped"][0] != -1:
                    tcp_count += 1

        udp_count /= trace_counts[instance_name]
        tcp_count /= trace_counts[instance_name]
        print("{}: udp:{} tcp:{}".format(instance_name, udp_count, tcp_count))

    print(f"udp {udp_count}, tcp {tcp_count}")

def compute_ipv4_ipv6_strip_stats(instances):
    pass

# Correlate the reachability of dns and ect codepoints
def compute_dns_tcp_ect_reachability(instances):

    # reachability of ect markings by host
    reachability = {}

    # get dns hosts that operate over both tcp and udp
    for instance in instances:
        count = 0
        for trace in instance["data"]:
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "dns_tcp" and x["is_host_reachable"], datum)) and \
                any(map(lambda x: x["proto"] == "dns_udp" and x["is_host_reachable"], datum)):
                    count += 1
        reachability[instance["name"]] = count
    return reachability

def compute_graph_of_hops(instances, host_select, proto, flag = 2):

    graph_size = 100
    count = 0
    raw_strip_data = []

    for instance in instances:
        if instance["name"] != 'us-east-1':
            continue
        for host, datum in instance["data"][0].items():
            if count > 100 or ":" in host:
                continue
            for x in datum:
                if x["proto"] == proto and x["flags"] == flag and len(x["is_ect_stripped"][-1]) < 17:
                    raw_strip_data.append((instance["name"], host,x["is_ect_stripped"]))
                    count += 1
    print("Recored strip data")
    pprint.pprint(raw_strip_data)
    import random
    raw_strip_data.sort(key=lambda x: len(x[1][-1]))

    
    dot = Graph(comment =   "A sample graph",
                format =    "png",
                engine =    "neato",
                graph_attr = [
                    ("ratio", "auto"),
                    ("ranksep","0.5"),
                    ("nodesep","0.5"),
                    ("overlap", "true")
                    ]
               )
    nodes = set()
    edges = set()

    node_attr = [("shape", "circle"),("style","filled")]

    for name, host,  instance in raw_strip_data:
        dot.node(name, "", _attributes=[*node_attr])
        prev = name
        nodes.add(name)
        strip, index, hop_distance, trace = instance

        def color_node(strip, hop):
            if hop < strip or strip == -1:
                return "green"
            else:
                return "red"
        
        def color_edge(strip, hop):
            if hop < strip or strip == -1:
                return "green"
            else:
                return "red"

        hop_outer = -1

        for hop,curr,_ in trace:

            if not curr in nodes:
                dot.node(curr, "", _attributes=[*node_attr, ("fillcolor", color_node(strip, hop))])
                nodes.add(curr)

            if prev and prev != curr and (prev,curr) not in edges:
                dot.edge(prev, curr, _attributes = [("color", color_edge(strip, hop))])
                edges.add((prev,curr))

            prev = curr
            hop_outer = hop
        # if not host in nodes:
        #     dot.node(host, "", _attributes=[("color", color_edge(strip, hop))])
        #     nodes.add(host)
        
        # if(prev, host) not in edges:
        #     dot.edge(prev,host, _attributes=[("color", color_edge(strip, hop_outer))])
        #     edges.add((prev,host))
    print(dot.source)
    dot.render("test_graph.pdf", view=True)


def compute_preserve_quic_graph(instances):
    hop_count = [0] * 64
    trace_count = 0
    for instance in instances:
        
        name = instance["name"]

        if "Part" in name:
            continue

        print(f"calc stats for {name}")
        for trace in instance["data"][-2:]:
            for host, datum in trace.items():
                for x in datum:
                    if x["proto"] == "quic_probe" and x["flags"] == 2:
                        trace_count += 1
                        if x["is_ect_stripped"][0] != -1:
                            hop_count[x["is_ect_stripped"][0]] += 1

    #trim of zero values
    hop_count = hop_count[::-1]
    trim = None
    for i, elt in enumerate(hop_count):
        if elt != 0:
            trim = i
            break

    hop_count = hop_count[trim:][::-1]
    print("trimming at {}".format(trim))
    print(hop_count)
    print(trace_count)


    total_remarked = sum(hop_count)
    hop_count = list(map(lambda x: (total_remarked - x) / total_remarked, np.cumsum(hop_count) ))


    xs = np.arange(1, len(hop_count)+1)
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.set_title("Graph presenting where on the path ECT removal is reported")
    ax1.set_xlabel('Interface hop')
    ax1.set_ylabel('Proportion')

    ax1.plot(xs, hop_count)
    fig.savefig("preservequic.pdf")
    


    print(hop_count)
    print(trace_count)


def compute_preserve_tcp_graph(instances):

    hop_count = [0] * 64
    trace_count = 0


    for instance in instances:
        if instance["name"] == "Participant-1":
            print("Skipping")
            continue
        for trace in instance["data"]:
            for host, datum in trace.items():
                for x in datum:
                    if x["proto"] == "tcp_probe" and x["flags"] == 2:
                        trace_count += 1
                        if x["is_ect_stripped"][0] != -1:
                            hop_count[x["is_ect_stripped"][0]] += 1
    

    #trim of zero values
    hop_count = hop_count[::-1]
    trim = None
    for i, elt in enumerate(hop_count):
        if elt != 0:
            trim = i
            break

    hop_count = hop_count[trim:][::-1]
    print("trimming at {}".format(trim))
    print(hop_count)
    print(trace_count)


    total_remarked = sum(hop_count)
    hop_count = list(map(lambda x: (total_remarked - x) / total_remarked, np.cumsum(hop_count) ))


    xs = np.arange(1, len(hop_count)+1)
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.set_title("Graph presenting where on the path ECT removal is reported")
    ax1.set_xlabel('Interface hop')
    ax1.set_ylabel('Proportion')

    ax1.plot(xs, hop_count)
    fig.savefig("preservetcp.pdf")
    


    print(hop_count)
    print(trace_count)



def compute_map_of_hosts(data_file):
    import pandas as pd
    import geopandas
    import matplotlib.pyplot as plt

    lats = []
    longs = []

    with open(data_file) as f:
        data = json.loads(f.read())
        for item in data:
            if item["latitude"] and item["longitude"]:
                lats.append(item["latitude"])
                longs.append(item["longitude"])

    df = pd.DataFrame(
        {
        'Latitude': lats,
        'Longitude': longs})

    gdf = geopandas.GeoDataFrame(
        df, geometry=geopandas.points_from_xy(df.Longitude, df.Latitude))

    world = geopandas.read_file(geopandas.datasets.get_path('naturalearth_lowres'))

    ax = world.plot(
        color='black', edgecolor='black')

    gdf.plot(ax=ax, color='#88CCEE', markersize=1.5, alpha=0.5)
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(f"{data_file}.map.pdf", bbox_inches='tight')

def compute_tcp_udp_bar_charts(instances):

    instance_data = {}
    max_seen = 0

    for i,instance in enumerate(instances):
        data = []
        instance_data[i] = data
        for trace in instance["data"]:
            udp_count = 0
            tcp_count = 0
            for host, datum in trace.items():
                if ":" in host:
                    continue
                # filter hosts that do not operate over both
                if not (any(map(lambda x: x["proto"] == "dns_tcp" and x["is_host_reachable"], datum)) and \
                    any(map(lambda x: x["proto"] == "dns_udp" and x["is_host_reachable"], datum))):
                    continue

                for x in datum:
                    if x["proto"] == "dns_udp_probe" and x["flags"] == 1 and x["is_ect_stripped"][0] != -1:
                        udp_count += 1
                    if x["proto"] == "dns_tcp_probe" and x["flags"] == 1 and x["is_ect_stripped"][0] != -1:
                        tcp_count += 1
            data.append({"udp":udp_count, "tcp":tcp_count})
            max_seen = max(udp_count, tcp_count) if max(udp_count, tcp_count) > max_seen else max_seen 

    print("stuff stuff stuff")
    pprint.pprint(instance_data)

    # graph the results
    fig, axs = plt.subplots(2, 5)
    fig.suptitle("Instances of ECT removal between UDP and TCP against IPv4 DNS resolvers")
    axs_re = axs.reshape(10)

    for ax, data in zip(axs_re, instance_data.items()):
        host, datums = data
        tcp_vals = [x["tcp"] for x in datums]
        udp_vals = [x["udp"] for x in datums]

        ind = np.arange(len(tcp_vals))
        width = 0.35

        ax.set_title(host)
        ax.set_ylim(0, max_seen)
        rects1 = ax.bar(ind - width/2, tcp_vals, width, label="tcp")
        rects2 = ax.bar(ind + width/2, udp_vals, width, label='Women')
    plt.show()
    print(max_seen)

def compute_interfaces(instances):
    
    clearing = set()
    clearing_as = set()
    
    maybe_clearing = set()
    maybe_clearing_as = set()

    non_clearing = set()
    non_clearing_as = set()
    boundary = 0
    non_boundary = 0
    
    for instance in instances:
        if instance["name"] == "Particpant-1":
            continue
        for trace in instance["data"]:
            for host, datum in trace.items():
                # check the trace data for reachable hosts

                for x in datum:
                    if not (x["proto"] == "tcp_probe" and x["flags"] == 2 and x["is_host_reachable"]):
                        continue

                    hop_remove, j, k, hops = x["is_ect_stripped"]
                    for i, elt  in enumerate(hops):
                        hop_count, interface, _ = elt
                        _, interface_next, _ = hops[i+1] if len(hops) - 1 > i else (None, None, None)
                        
                        auto = connection.get(interface)
                        if not auto:
                            auto = lib.whois.WhoIs.instance().lookup(interface)
                            if not auto:
                                print("still returning none :/")
                        asn = json.loads(auto)["asn"]

                        if interface_next:
                            asn_next = json.loads(connection.get(interface_next))["asn"]

                        if hop_remove + 1 == hop_count and hop_remove != -1:
                            if interface in non_clearing:
                                maybe_clearing.add(interface)
                                non_clearing.remove(interface)
                            else:
                                clearing.add(interface)
                                clearing_as.add(asn)
                            
                            if not (asn in [None, "private"] or asn_next in [None, "private"]):
                                if interface_next:
                                    if asn != asn_next:
                                        print("{} - {}".format(asn, asn_next))
                                        boundary += 1
                                    else:
                                        non_boundary += 1


                        elif not interface in clearing:
                            non_clearing.add(interface)
                            non_clearing_as.add(asn)


                        else:
                            clearing.remove(interface)
                            maybe_clearing.add(interface)
                            maybe_clearing_as.add(asn)


    print("clearing: {}".format(len(clearing)))
    print("non clearing: {}".format(len(non_clearing)))
    print("maybe clearing: {}".format(len(maybe_clearing)))

    print("clearing {}".format(len(clearing_as)))
    print("maybe clearing {}".format(len(maybe_clearing_as)))
    print("not clearing {}".format(len(non_clearing_as)))

    print("boundary remarking: {}\nNon boundary remarking: {}".format(boundary, non_boundary))

def compute_interfaces_ntp(instances):
    
    clearing = set()
    clearing_as = set()
    
    maybe_clearing = set()
    maybe_clearing_as = set()

    non_clearing = set()
    non_clearing_as = set()
    boundary = 0
    non_boundary = 0
    
    for instance in instances:
        if instance["name"] == "ian":
            continue
        if instance["name"] == "pi":
            continue
        if instance["name"] == "us-east-1":
            continue
        for trace in instance["data"]:
            for host, datum in trace.items():
                # check the trace data for reachable hosts

                for x in datum:
                    if not (x["proto"] == "ntp_udp_probe" and x["flags"] == 2 and x["is_host_reachable"]):
                        continue

                    hop_remove, j, k, hops = x["is_ect_stripped"]
                    for i, elt  in enumerate(hops):
                        hop_count, interface, _ = elt
                        _, interface_next, _ = hops[i+1] if len(hops) - 1 > i else (None, None, None)
                        
                        auto = connection.get(interface)
                        if not auto:
                            auto = lib.whois.WhoIs.instance().lookup(interface)
                            if not auto:
                                print("still returning none :/")
                        asn = json.loads(auto)["asn"]

                        if interface_next:
                            asn_next = json.loads(connection.get(interface_next))["asn"]

                        if hop_remove + 1 == hop_count and hop_remove != -1:
                            if interface in non_clearing:
                                maybe_clearing.add(interface)
                                non_clearing.remove(interface)
                            else:
                                clearing.add(interface)
                                clearing_as.add(asn)
                            
                            if not (asn in [None, "private"] or asn_next in [None, "private"]):
                                if interface_next:
                                    if asn != asn_next:
                                        print("{} - {}".format(asn, asn_next))
                                        boundary += 1
                                    else:
                                        non_boundary += 1


                        elif not interface in clearing:
                            non_clearing.add(interface)
                            non_clearing_as.add(asn)


                        else:
                            clearing.remove(interface)
                            maybe_clearing.add(interface)
                            maybe_clearing_as.add(asn)


    print("clearing: {}".format(len(clearing)))
    print("non clearing: {}".format(len(non_clearing)))
    print("maybe clearing: {}".format(len(maybe_clearing)))

    print("clearing {}".format(len(clearing_as)))
    print("maybe clearing {}".format(len(maybe_clearing_as)))
    print("not clearing {}".format(len(non_clearing_as)))

    print("boundary remarking: {}\nNon boundary remarking: {}".format(boundary, non_boundary))


def as_traversal_table_data(instances):

    table_dat = [[0] * (i+1) for i in range(1,25)]

    for instance in instances:
        if instance["name"] == "Participant-1":
            continue
        for trace in instance["data"]:
            for host, datum in trace.items():
                for x in datum:
                    if not (x["proto"] == "tcp_probe" and x["flags"] == 2 and x["is_host_reachable"]):
                        continue

                    hop_remove, j, k, hops = x["is_ect_stripped"]
                    prev_as = None
                    curr_as = None
                    as_strip = -1
                    as_count = 0

                    # if ect is not stripped
                    if hop_remove == -1:
                        continue

                    for i, elt  in enumerate(hops):
                        hop_count, interface, _ = elt
                        curr_as = json.loads(connection.get(interface))["asn"]
                        
                        if curr_as == "NA":
                            curr_as = prev_as

                        if prev_as == None:
                            prev_as == curr_as

                        elif prev_as != curr_as and prev_as != "private":
                            as_count += 1

                        if hop_remove + 1 == hop_count and hop_remove != -1:
                            as_strip = as_count
                        prev_as = curr_as

                    if as_strip != -1:
                        table_dat[as_count][as_strip] += 1
    sums = []
    print(table_dat)
    for sub in table_dat:
        # private addresses from src network
        # we just attribute these to the 1st AS
        sub.pop(0)
        tot = sum(sub)
        sums.append(tot)
        csum = np.cumsum(sub)
        if not tot:
            continue
        prop = list(map(lambda x: x / tot, sub))
        print(prop)
                    
    print(sums)
    
    pass

def compute_strip_stats_ntp(instances):
    
    traces = []

    for instance in instances:
        count = 0
        total = 0
        

        for trace in instance["data"]:
            for host, datum in trace.items():
                for x in datum:
                    if x["proto"] == "ntp_udp_probe" and x["flags"] == 2:
                        if x["is_ect_stripped"][0] != -1:
                            count += 1
                        total += 1
        
        traces.append( [instance["name"], count / len(instance["data"]), (count/total) * 100 ] )
    print(traces)

def compute_tcp_bar_charts(instances):

    instance_data = {}
    max_seen = 0

    for i,instance in enumerate(instances):
        data = []
        vantage = instance["name"]
        instance_data[i] = data
        for trace in instance["data"]:
            tcp_count = 0
            for host, datum in trace.items():
                if ":" in host:
                    continue

                for x in datum:
                    if x["proto"] == "tcp_probe" and x["flags"] == 2 and x["is_ect_stripped"][0] != -1:
                        tcp_count += 1
            data.append({"name": vantage, "tcp":tcp_count})
            if tcp_count > max_seen:
                max_seen = tcp_count
    pprint.pprint(instance_data)

    # graph the results
    fig, axs = plt.subplots(4, 3)
    fig.suptitle("Instances of ECT removal under TCP against IPv4 Web servers")
    axs_re = axs.reshape(12)

    for ax, data in zip(axs_re, instance_data.items()):
        host, datums = data
        tcp_vals = [x["tcp"] for x in datums]

        ind = np.arange(len(tcp_vals))
        width = 0.35

        ax.set_title(datums[0]["name"])
        ax.set_ylim(0, max_seen)
        ax.get_xaxis().set_ticks([])
        rects1 = ax.bar(ind, tcp_vals, width, label="TCP")

    fig.text(0.5, 0.04, 'Traces', ha='center')
    fig.text(0.04, 0.5, 'Count', va='center', rotation='vertical')
    fig.set_size_inches( 8.5, 7.5)
    plt.savefig("tcp_bar.pdf")

        
def dns_udp_tcp_pairing(instances):

    counts = {}

    for instance in instances:
        matched = 0
        matched_as = 0
        not_matched = 0
        not_matched_as = 0
        for trace in instance["data"]:
            for host, datum in trace.items():
                tcp_trace = None
                udp_trace = None
                for x in datum:
                    if x["proto"] == "dns_udp_probe" and x["flags"] == 0x02 and x["is_host_reachable"] and x["is_ect_stripped"][0] != -1:
                        udp_trace = x
                    if x["proto"] == "dns_tcp_probe" and x["flags"] == 0x02 and x["is_host_reachable"] and x["is_ect_stripped"][0] != -1:
                        tcp_trace = x
            
                if not tcp_trace or not udp_trace:
                    continue

                hop_remove, j, k, hops = tcp_trace["is_ect_stripped"]
                tcp_dev = None
                udp_dev = None

                for hop_count, interface, _ in hops:
                    if hop_count == hop_remove:
                        tcp_dev = interface
                        break

                hop_remove, j, k, hops = udp_trace["is_ect_stripped"]
                for hop_count, interface, _ in hops:
                    if hop_count == hop_remove:
                        udp_dev = interface
                        break

                tcp_as = connection.get(tcp_dev)
                udp_as = connection.get(udp_dev)

                if tcp_as and udp_as:
                    if json.loads(tcp_as)["asn"] == json.loads(udp_as)["asn"]:
                        matched_as += 1
                    else:
                        not_matched_as += 1

                if tcp_dev == udp_dev:
                    matched+=1
                else:
                    print("{} != {}".format(tcp_dev, udp_dev))
                    not_matched+=1

        avg = len(instance["data"])
        counts[instance["name"]] = [matched/avg, not_matched/avg, matched_as/avg, not_matched_as/avg]
    pprint.pprint(counts)

def compute_remarking_tcp_ip6(instances):
    results = [{}, {}, {}, {}]

    for instance in instances:
        for trace in instance["data"]:
            for host, datum in trace.items():
                if not ":" in host:
                    continue


                for x in datum:
                    if x["proto"] == "dns_udp_probe" and x["flags"] != 0:
                        for hop, interface, tos in x["is_ect_stripped"][-1]:
                            dscp = tos & 0xFC
                            ecn = tos & 0x03
                            
                            if tos & 0x03 != x["flags"] or dscp != 0x00:
                                if (dscp , ecn) in results[x["flags"]]:
                                    results[x["flags"]][(dscp ,ecn)] += 1
                                else:
                                    results[x["flags"]][(dscp, ecn)] = 1
                                if ecn != x["flags"]:
                                    break
    pprint.pprint(results)

def compute_remarking_tcp(instances):
    results = [{}, {}, {}, {}]
    print(results)
    for instance in instances:
        if instance["name"] == "ian":
            continue
        print("do remarking for instance: \"{}\"".format(instance["name"]))
        for trace in instance["data"]:
            for host, datum in trace.items():
                #look for where ECT is remarked on the network
                #compute a table of the common remarking for each codepoint
                
                #are codepoints remarked to other codepoints
                #are some changed to others
                #does this generally happen with a change to the ToS byte

                for x in datum:
                    if x["proto"] == "dns_udp_probe" and x["flags"] != 0:
                        for hop, interface, tos in x["is_ect_stripped"][-1]:
                            dscp = tos & 0xFC
                            ecn = tos & 0x03
                            
                            if tos & 0x03 != x["flags"] or dscp != 0x00:
                                if (dscp , ecn) in results[x["flags"]]:
                                    results[x["flags"]][(dscp ,ecn)] += 1
                                else:
                                    results[x["flags"]][(dscp, ecn)] = 1
                                if ecn != x["flags"]:
                                    break

    pprint.pprint(results)
    
    for i, elt in enumerate(results):
        total = 0        
        for tos, count in elt.items():
            dscp, ecn = tos
            if ecn == 0 and dscp != 0:
                total += count
        print(total)

def compute_tcp_strip_stats(instances):

    results = {}
    for instance in instances:
        # one for each codepoint, ignore 0 to make indexing nicer
        instance_results = []
        for trace in instance["data"]:
            total_count = 0
            trace_results = [0] * 4
            for host, datum in trace.items():
                tcp_traces = []
                for x in datum:
                    if x["proto"] == "tcp_probe" and x["flags"] != 0 and x["is_host_reachable"]:
                        tcp_traces.append(x)
                if not tcp_traces:
                    continue
                total_count += 1
                for ect_trace in tcp_traces:
                    if ect_trace["is_ect_stripped"][0] != -1:
                        trace_results[ect_trace["flags"]] += 1
            instance_results.append(trace_results)

        div = len(instance_results)
        sums = [0] * 4

        # get the average across traces
        for _, e1, e2, e3 in instance_results:
            sums[1] += e1
            sums[2] += e2
            sums[3] += e3
        sums = list(map(lambda x: x/div, sums))
        sums_prop = list(map(lambda x: x/total_count, sums ))
        results[instance["name"]] = (sums, sums_prop)
    print("strip stats")
    print(results)




def conduct_analysis(instances, dataset_dir="../../datasets"):
    '''
        The main body of analysis
        in here we generate graphs
    '''
    
    generate_ecn_trends_graph("ecn_trends.txt")

    # print("attempt to map web hosts")
    # compute_map_of_hosts("ntp.locs")
    # compute_map_of_hosts("web.locs")
    # compute_map_of_hosts("dns.locs")
   
    stats = {}

    for instance in instances:
        if instance["name"] == "ian":
            del instance["data"][2]
        if instance["name"] == "pi":
            del instance["data"][1]

    # stats["reachability udp ntp"] = compute_reachability_stats_udp_ntp(instances)
    stats["ect_stripped_udp_ntp"] = compute_basic_strip_stats_udp_ntp(instances)
    # stats["ect_stripped_tcp_web"] = compute_basic_strip_stats_tcp_web(instances)
    # stats["ect_probe_tcp_web"] = compute_basic_strip_stats_tcp_web_probe(instances)
    # stats["ecn_negotiated"] = compute_basic_ecn_negotation_stats(instances)
    # stats["ecn_negotiated_quic"] = compute_ecn_negotiation_quic(instances)
    # stats["ect_stripped_quic"] = compute_ect_stripped_quic(instances)
    # stats["dns_both_tcp_udp"] = compute_dns_tcp_ect_reachability(instances)
    # compute_cdf_tcp_ect(instances)
    # compute_cdf_quic_ect(instances)
    # compute_tcp_udp_strip_stats(instances)
    # compute_tcp_udp_correlation(instances)
    #  "69.171.250.35", "74.6.231.20" "216.58.210.206", 
    # compute_graph_of_hops(instances, [
    #     "78.36.18.184",
    #     "3.114.30.212",
    #     "92.243.6.5",
    #     "178.33.203.115",
    #     "208.88.126.235",
    #     "45.33.31.34",
    #     "212.186.223.161",
    #     "94.172.186.238",
    #     "66.79.136.235",

    # ], "tcp_probe")
    
    # compute_tcp_bar_charts(instances)
    # compute_preserve_tcp_graph(instances)
    # compute_preserve_quic_graph(instances)
    
    # compute_tcp_udp_bar_charts(instances)
    # compute_tcp_udp_strip_stats(instances)
    
    # compute_tcp_udp_correlation(instances)
    # ect_marked_icmp_stats(instances)
    # ipv4_ipv6_stuff(instances)
    pprint.pprint(stats)
    # compute_interfaces(instances)
    compute_interfaces_ntp(instances)
    # as_traversal_table_data(instances)
    # dns_udp_tcp_pairing(instances)
    # compute_strip_stats_ntp(instances)
    compute_remarking_tcp(instances)
    # compute_remarking_tcp_ip6(instances)
    # compute_tcp_strip_stats(instances)
    pass