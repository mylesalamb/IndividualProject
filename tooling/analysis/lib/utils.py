import os
import glob

file_types = [
              "tcp", "quic", "ntp_udp",
              "ntp_tcp","dns_udp", "dns_tcp",
              "tcp_probe", "quic_probe", "ntp_tcp_probe",
              "ntp_udp_probe","dns_tcp_probe","dns_udp_probe"
             ]

# identifiers to file types
file_globs = {elt: "*-{i}-*".format(i=elt.upper()) for elt in file_types}


class ConnectionContext(object):
    '''Simple wrapper for connection contexts'''
    
    
    def __init__(self,context: str):
        self.host = ""
        self.proto = ""
        self.flags = []
        
        context.split('-')
    
    def parse_pcap_file_name(file: str):
        name, _ = os.path.splitext(file)
        try:
            host, conn_type, *flags = name.split('-')
        except:
            print(f"Err parsing file name: {file}")
            return None

def _get_abs_sub_dirs(directory: str):
    return [os.path.join(directory, elt)  for elt in os.listdir(directory)]
    
# get files from output directory
def get_instances(data_dir: str):
    return _get_abs_sub_dirs(data_dir)
        
def get_traces(instance_dir: str):
    return _get_abs_sub_dirs(instance_dir)

def get_pcap_from_trace(trace_dir: str, glob_str: str = None):
    
    if not glob:
        return _get_abs_sub_dirs(trace_dir)
    
    globed_path = os.path.join(trace_dir, glob_str)
    return glob.glob(globed_path)


def get_instance_traces(indir: str):
    instances = get_instances(os.path.expanduser(indir))
    inputs = []
    for instance in instances:
        print("getting instace: {}".format(instance))
        dic = {}
        dic["name"] = os.path.basename(instance)
        traces = get_traces(instance)

        dic["traces"] = []
        for trace in traces:
            globs = {}
            print("resolve instance: {}, trace {}".format(instance, trace))
            globs = {k:get_pcap_from_trace(trace, v) for k,v in file_globs.items()}
            dic["traces"].append(globs)

        inputs.append(dic)
    return inputs


