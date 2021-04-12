#!/usr/bin/python

import json

ALEXA_SITES = "web.alexa.raw"
FILTER_SITES = "domains.filter.dataset"

# get the domains from file contain lines with domains
def get_filter_set(filename : str):
    ret_set = None
    with open(filename) as f:
        ret_set = set([domain.strip() for domain in f])
    return ret_set

def get_alexa_sites(filename : str):
    ret_domains = []
    with open(filename) as f:
        data =  json.loads(f.read())

    for elt in data:
        ret_domains.append(elt["Ats"]["Results"]["Result"]["Alexa"]["TopSites"]["Country"]["Sites"]["Site"]["DataUrl"])
    return ret_domains
            


def main():
    print("### filter alexa top sites for explicit domains ###")
    ret = get_alexa_sites(ALEXA_SITES)
    filter_set = get_filter_set(FILTER_SITES)

    filtered = list(filter(lambda x: x not in filter_set, ret))
    excluded = list(filter(lambda x: x in filter_set, ret))

    print(f"Length of dataset before {len(ret)}")
    print(f"Length of dataset after {len(filtered)}")
    print(f"excluded sites {excluded}")

    with open("alexa.filtered.dataset", "w") as f:
        for domain in filtered[:1000]:
            f.write(f"{domain}\n")

if __name__ == "__main__":
    main()
