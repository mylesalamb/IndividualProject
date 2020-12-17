import os
import logging
from scapy.all import *
from lib.utils import file_types
import pprint


def add_metric(typeArg):
    def wrapper(f):
        print(f"wrapping {f.__name__} to {typeArg.__name__}")
        typeArg.add_metric_strategy(f)
        def wrapped_call(*args):
            f(*args)
        return wrapped_call
    return wrapper

def all_subclasses(cls, incl_cls=False):
    
    subclasses = []

    if(incl_cls):
        subclasses.append(cls)

    for subclass in cls.__subclasses__():
        subclasses.append(subclass)
        subclasses.extend(all_subclasses(subclass))

    return subclasses

def impl_metric_base_class(class_arg):

    @classmethod
    def add_metric_strategy(cls, func):
        
        for sub in all_subclasses(cls, True):
            v = class_arg._metrics.get(sub.__name__)
            if not v:
                class_arg._metrics[sub.__name__] = [func]
            else:
                v.append(func)

        pprint.pprint(class_arg._metrics)
    @property
    def metrics(self):
        return self._metrics.get(self.__class__.__name__)
    
    setattr(class_arg, "_metrics", {k.__name__:[] for k in all_subclasses(class_arg, True)})
    setattr(class_arg, "add_metric_strategy", add_metric_strategy)
    setattr(class_arg, "metrics", metrics)
    return class_arg

class ParserFactory(object):

    def __init__(self):
        self.parsers = {k:None for k in file_types}
        
        self.parsers["tcp"] = TCPConnectonParser
        self.parsers["tcp_probe"] = TCPProbeParser
        
        self.parsers["ntp_udp"] = UDPConnectionParser
        self.parsers["ntp_udp_probe"] = UDPProbeParser

        self.parsers["dns_udp"] = UDPConnectionParser
        self.parsers["dns_udp_probe"] = UDPProbeParser
        
        self.parsers["ntp_tcp"] = TCPConnectonParser
        self.parsers["ntp_tcp_probe"] = TCPProbeParser
        
        self.parsers["dns_tcp"] = TCPConnectonParser
        self.parsers["dns_tcp_probe"] = TCPProbeParser
        
        self.parsers["quic"] = QuicConnectionParser
        self.parsers["quic_probe"] = QuicProbeParser
        

    def get_parser(self, file):
        print(file)
        host, proto, *flags = file.split('-')
        parser = self.parsers.get(proto.lower())

        if parser:
            return parser
        else:
            raise ValueError("Not a valid file to parse")



class ConnectionContext(object):
    
    def __init__(self, filename):
        filename, _ = os.path.splitext(filename)
        self.host, proto, *flags = filename.split('-')
        self.proto = proto.lower()
        self.flags = [int(flag, 16) for flag in flags]

@impl_metric_base_class
class Parser(object):

    # take the full path for a file
    # and initialise the state of the parser
    def __init__(self, file):
        self.my_metrics = self.metrics
        self.packets = None
        self.ctx = None
        self.output = None

        self.output = {}
        self.packets = rdpcap(file)
        self.ctx = ConnectionContext(os.path.basename(file))    

    def run(self):
        outputs = {}
        for func in self.my_metrics:
            outputs[func.__name__] = func(self.packets, self.ctx)
        print(outputs)

        return outputs
        

class ProbeParser(Parser):
    pass


class UDPProbeParser(ProbeParser):
    pass


class TCPProbeParser(ProbeParser):
    pass

class ConnectionParser(Parser):
    pass

class TCPConnectonParser(ConnectionParser):
    pass

class UDPConnectionParser(ConnectionParser):
    pass

class QuicConnectionParser(UDPConnectionParser):
    pass

class QuicProbeParser(UDPProbeParser):
    pass
