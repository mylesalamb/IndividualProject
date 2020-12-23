import os
import sys
import argparse
import pprint
from lib import utils, parsers, strategies
from typing import Any
import logging

def resolve_instance(instance):
    print(f"resolving instance: {instance['name']}")

    factory = parsers.ParserFactory()
    
     
    for trace_type in instance["traces"]:
        print(trace_type)

        trace_files = instance["traces"][trace_type]

        if not trace_files:
            continue

        parser_type = factory.get_parser(os.path.basename(trace_files[0]))

        for trace in trace_files:
            print(trace)
            p = parser_type(trace)
            result = p.run()
            print(result)
        



def parse_arguments(args:str = sys.argv[1:]):

    parser = argparse.ArgumentParser(description = "Data analysis tool for pcap files")
    parser.add_argument("-i", "--indir", help="input data directory", default="~/outdata")

    args = parser.parse_args(args)
    return vars(args)

def main():
    in_args = parse_arguments()
    raw_data = utils.get_instance_traces(in_args["indir"])
    pprint.pprint(raw_data)
    resolve_instance(raw_data[0])

    


if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO)
    main()