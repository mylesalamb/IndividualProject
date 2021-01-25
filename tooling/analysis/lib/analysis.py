
import pprint
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


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


    print(datums_raw[0])

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
    ax1.set_title("Cumulative density function\nrepresenting where on the path ect codepoints are cleared\nfor Webserver hosts")
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
        
        plots.append(mpatches.Patch(color=ect_color[i], label=f'ECT({i+1}) traces'))
    plt.legend(handles=plots)
        
    plt.xlim([0, 1])
    plt.ylim([0, 1])

    fig.savefig(f"test.svg")

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




def compute_tcp_udp_strip_stats(instances):
    pass


def compute_ipv4_ipv6_strip_stats(instances):
    pass





def compute_aux_structures(instances):
    ''' 
        Data coercion to numpy / pandas arrays
        Make data much more amenable to data analysis
    '''
    pass

def conduct_analysis(instances):
    '''
        The main body of analysis
        in here we generate graphs
    '''
    global ntp_hosts, web_hosts, dns_hosts

    # # Do Web
    # for key,elt in instance.get("data").items():
    #     if any(map(lambda x: x["proto"] == "quic", elt)):
    #         web_hosts.append(elt)

    # # Do NTP
    # for key,elt in instance.get("data").items():
    #     if any(map(lambda x: x["proto"] == "ntp_tcp", elt)):
    #         ntp_hosts.append(elt)

    # # Do Dns
    # for key,elt in instance.get("data").items():
    #     if any(map(lambda x: x["proto"] == "dns_tcp", elt)):
    #         dns_hosts.append(elt)

    stats = {}

    stats["reachability"] = compute_reachability_stats_udp_ntp(instances)
    stats["ect_stripped_udp_ntp"] = compute_basic_strip_stats_udp_ntp(instances)
    stats["ect_stripped_tcp_web"] = compute_basic_strip_stats_tcp_web(instances)
    stats["ecn_negotiated"] = compute_basic_ecn_negotation_stats_web(instances)
    stats["ecn_negotiated_quic"] = compute_ecn_negotiation_quic(instances)
    stats["ect_stripped_quic"] = compute_ect_stripped_quic(instances)
    compute_cdf_tcp_ect(instances)
    pprint.pprint(stats)

    
    pass