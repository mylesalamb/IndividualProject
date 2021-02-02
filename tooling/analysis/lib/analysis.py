import pprint
from graphviz import Graph
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import geoip2.database
import json

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

def compute_basic_ecn_negotation_stats_web(instances):
    results = {}
    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            web_hosts = []
            ecn_negotatiated = [0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "tcp", datum)):
                    web_hosts.append((host, datum))

            for host, data in web_hosts:
                for stat in data:
                    if stat["proto"] == "tcp" and stat["flags"] == 1:
                        if stat["is_ecn_negotiated_tcp"]:
                            ecn_negotatiated[1] += 1
                        else:
                            ecn_negotatiated[0] += 1

            results[name].append(ecn_negotatiated)

    return results


def compute_ecn_negotiation_quic(instances):
    results = {}
    for instance in instances:
        
        name = instance["name"]
        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"]:
            web_hosts = []
            ecn_negotatiated = [0,0]
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "quic", datum)):
                    web_hosts.append((host, datum))

            for host, data in web_hosts:
                for stat in data:
                    if stat["proto"] == "quic" and stat["flags"] == 1:
                        if stat["is_ecn_negotiated_quic"]:
                            ecn_negotatiated[1] += 1
                        else:
                            ecn_negotatiated[0] += 1

            results[name].append(ecn_negotatiated)

    return results

def compute_ect_stripped_quic(instances):

    results = {}
    for instance in instances:
        
        name = instance["name"]

        if not "-" in name:
            continue

        results[name] = []

        print(f"calc stats for {name}")
        for trace in instance["data"][-2:]:
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




def compute_tcp_udp_strip_stats(instances):
    
    hosts = []

    # get dns hosts that operate over both tcp and udp
    for instance in instances:
        for trace in instance["data"]:
            for host, datum in trace.items():
                if any(map(lambda x: x["proto"] == "dns_tcp" and x["is_host_reachable"], datum)) and \
                any(map(lambda x: x["proto"] == "dns_udp" and x["is_host_reachable"], datum)):
                    hosts.append((host, datum))
    
    udp_count = 0
    tcp_count = 0
    
    for host, datum in hosts:
        for elt in datum:
            if elt["proto"] == "dns_udp_probe" and elt["flags"] == 2 and elt["is_ect_stripped"][0] != -1:
                udp_count +=1
            if elt["proto"] == "dns_tcp_probe" and elt["flags"] == 2 and elt["is_ect_stripped"][0] != -1:
                tcp_count += 1
    
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

def compute_tcp_udp_correlation(instances):

    for instance in instances:
        counts = []
        for trace in instance["data"]:
            udp_count = 0
            tcp_count = 0
            for host, datum in trace.items():
                
                # filter hosts that do not operate over both
                if not (any(map(lambda x: x["proto"] == "dns_tcp" and x["is_host_reachable"], datum)) and \
                    any(map(lambda x: x["proto"] == "dns_udp" and x["is_host_reachable"], datum))):
                    continue

                for x in datum:
                    if x["proto"] == "dns_udp_probe" and x["flags"] == 1 and x["is_ect_stripped"][0] != -1:
                        udp_count += 1
                    if x["proto"] == "dns_tcp_probe" and x["flags"] == 1 and x["is_ect_stripped"][0] != -1:
                        tcp_count += 1
            counts.append((udp_count, tcp_count))
        udp_fin = sum([u for u,_ in counts]) / len(counts)
        tcp_fin = sum([t for _,t in counts]) / len(counts)
        print(f"tcp: {tcp_fin}, udp: {udp_fin}")              

            
    return

def compute_graph_of_hops(instances, host_select, proto, flag = 1):

    raw_strip_data = []

    for instance in instances:
        for trace in instance["data"]:
            for host, datum in trace.items():
                if host != host_select:
                    continue
                for x in datum:
                    if x["proto"] == proto and x["flags"] != 0:
                        raw_strip_data.append(x["is_ect_stripped"])

    print("Recored strip data")
    pprint.pprint(raw_strip_data)

    dot = Graph(comment = "A sample graph", format="svg", engine="circo")
    nodes = set()

    node_attr = [("shape", "circle"),("style","filled")]

    for instance in raw_strip_data:
        prev = None
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


        for hop,curr in trace:

            if not curr in nodes:
                dot.node(curr, "", _attributes=[*node_attr, ("fillcolor", color_node(strip, hop))])
                nodes.add(curr)

            if prev and prev != curr:
                dot.edge(prev, curr, _attributes = [("color", color_edge(strip, hop))])

            prev = curr
        if not host in nodes:
            dot.node(host, "", _attributes=[*node_attr])
            nodes.add(host)
        dot.edge(prev,host, _attributes=[("color", color_edge(strip, hop))])
    dot.unflatten(stagger=3)
    dot.render('test.gv', view=True)


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

    gdf.plot(ax=ax, color='#88CCEE', markersize=2, alpha=0.7)
    plt.axis('off')
    plt.savefig(f"{data_file}.map.svg")

def compute_tcp_udp_bar_charts(instances):

    instance_data = {}
    max_seen = 0

    for instance in instances:
        data = []
        instance_data[instance["name"]] = data
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

        

    

def compute_aux_structures(instances):
    ''' 
        Data coercion to numpy / pandas arrays
        Make data much more amenable to data analysis
    '''
    pass

def conduct_analysis(instances, dataset_dir="../../datasets"):
    '''
        The main body of analysis
        in here we generate graphs
    '''
    

    print("attempt to map web hosts")
    compute_map_of_hosts("ntp.locs")
    compute_map_of_hosts("web.locs")
    compute_map_of_hosts("dns.locs")
   
    stats = {}

    stats["reachability udp ntp"] = compute_reachability_stats_udp_ntp(instances)
    stats["ect_stripped_udp_ntp"] = compute_basic_strip_stats_udp_ntp(instances)
    stats["ect_stripped_tcp_web"] = compute_basic_strip_stats_tcp_web(instances)
    stats["ecn_negotiated"] = compute_basic_ecn_negotation_stats_web(instances)
    stats["ecn_negotiated_quic"] = compute_ecn_negotiation_quic(instances)
    stats["ect_stripped_quic"] = compute_ect_stripped_quic(instances)
    stats["dns_both_tcp_udp"] = compute_dns_tcp_ect_reachability(instances)
    compute_cdf_tcp_ect(instances)
    compute_cdf_quic_ect(instances)
    compute_tcp_udp_strip_stats(instances)
    compute_tcp_udp_correlation(instances)
    #compute_graph_of_hops(instances, "203.190.58.50", "tcp_probe")
    pprint.pprint(stats)
    compute_tcp_udp_bar_charts(instances)
    
    pass