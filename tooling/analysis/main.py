import os
import sys
import argparse
import pprint
import json
from lib import utils, parsers, strategies
from typing import Any
import logging

def resolve_instance(instance):
    print(f"resolving instance: {instance['name']}")
    instance["data"] = []

    for trace in instance["traces"]:
        outdata = {}
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

                if ctx.host in outdata:
                    outdata[ctx.host].append(result)
                else:
                    outdata[ctx.host] = [result]
        instance["data"].append(outdata)

    del instance["traces"]
    return instance





def parse_arguments(args:str = sys.argv[1:]):

    parser = argparse.ArgumentParser(description = "Data analysis tool for pcap files")
    parser.add_argument("-i", "--indir", help="input data directory", default="~/outdata")
    parser.add_argument("-f", "--from-json", help="Pre calculated json file, so we dont re-run slow file interactions")
    parser.add_argument("-o", "--output-directory", help="Output directory for files")

    args = parser.parse_args(args)
    return vars(args)

def main():
    in_args = parse_arguments()

    if not in_args["output_directory"] or not os.path.exists(in_args["output_directory"]):
        print("invalid output directory")
        exit(1)
    

    if not in_args["from_json"]:
        print("Getting data from {}...".format(in_args["indir"]))
        raw_data = utils.get_instance_traces(in_args["indir"])
        in_args = []
        for instance_data in raw_data:
            instance = resolve_instance(instance_data)

            ofile = "{}.json".format(instance_data["name"])

            with open(ofile, "w") as f:
                json.dump(instance, f)

if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO)
    main()
