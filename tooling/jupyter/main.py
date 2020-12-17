import os
import sys
import argparse
from lib import utils, parsers, strategies
from typing import Any
import logging

def resolve_instance(instance):
    print(f"resolving instance: {instance['name']}")

    factory = parsers.ParserFactory()

    parser = factory.get_parser(os.path.basename(instance["traces"]["ntp_udp"][0]))
     
    for trace in instance["traces"]["ntp_udp"]:
        print(trace)
        conn_parser = parser(trace)
        conn_parser.run()



def parse_arguments(args:str = sys.argv[1:]):

    parser = argparse.ArgumentParser(description = "Data analysis tool for pcap files")
    parser.add_argument("-i", "--indir", help="input data directory", default="~/outdata")

    args = parser.parse_args(args)
    return vars(args)

def main():
    in_args = parse_arguments()
    raw_data = utils.get_instance_traces(in_args["indir"])
    resolve_instance(raw_data[0])

    


if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO)
    main()