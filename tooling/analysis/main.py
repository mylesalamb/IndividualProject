import os
import sys
import argparse
import pprint
import json
from lib import utils, parsers, strategies
from lib.whois import WhoIs
from lib.analysis import compute_aux_structures, conduct_analysis

from typing import Any
import logging

def resolve_instance(instance):
    print(f"resolving instance: {instance['name']}")
    instance["data"] = []
    
    for i,trace in enumerate(instance["traces"]):
        data = {}
        for trace_type in trace:
            
            pprint.pprint(trace_type)

            trace_files = trace[trace_type]

            if not trace_files:
                continue
            
            factory = parsers.ParserFactory()
            parser_type = factory.get_parser(os.path.basename(trace_files[0]))

            for conn in trace_files:
                p = parser_type(conn)
                ctx,result = p.run()
                
                result["proto"] = ctx.proto
                result["flags"] = ctx.flags

                if ctx.host in data:
                    data[ctx.host].append(result)
                else:
                    data[ctx.host] = [result]
        instance["data"].append(data)

    del instance["traces"]
    return instance


def parse_arguments(args:str = sys.argv[1:]):

    parser = argparse.ArgumentParser(description = "Data analysis tool for pcap files")
    parser.add_argument("-i", "--indir", help="input data directory", default="~/outdata")
    parser.add_argument("-w", "--whoiscache", help="cache directory for who-is data")
    parser.add_argument("-f", "--from-json", help="Pre calculated json file, so we dont re-run slow file interactions")
    parser.add_argument("-o", "--output-directory", help="Output directory for files")
    parser.add_argument("-r", "--run-analysis", help="Flag to toggle", action="store_true")

    args = parser.parse_args(args)
    return vars(args)

def main():
    in_args = parse_arguments()
    
    if not in_args["output_directory"] or not os.path.exists(in_args["output_directory"]):
        print("invalid output directory")
        exit(1)

    WhoIs.instance(in_args["whoiscache"])
    
    if not in_args["from_json"]:
        print("Getting data from {}...".format(in_args["indir"]))
        instances = []
        raw_data = utils.get_instance_traces(in_args["indir"])
        for instance_data in raw_data:
            instance = resolve_instance(instance_data)
            ofile = "{}.json".format(instance_data["name"])
            with open(ofile, "w") as f:
                json.dump(instance, f)
            instances.append(instance)
    else:
        # We've been given a checkpointed set of files
        print(f"Attempt to recover data from a collection of Json files")
        instances = utils.recover_instances_from_file(in_args["from_json"])

    if in_args["run_analysis"]:
        print("Would run analysis from here on")
        compute_aux_structures(instances)
        conduct_analysis(instances)
    
    WhoIs.instance().cleanup()


    

if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO)
    main()
