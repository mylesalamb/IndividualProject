'''
Convenience wrapper and utils around ipwhois

We cache results here to help prevent throttling from the registries,
some inparticular are rather nasty with this. Hence caching is essential
'''
import os
import json
from ipwhois.net import Net
from ipwhois.asn import IPASN

WHOIS_CACHE_FILE = "cache.whois"

class WhoIs:

    _instance = None

    @classmethod
    def instance(cls, file_loc=None):
        if cls._instance == None:
            if file_loc:
                file_loc = os.path.join(file_loc, WHOIS_CACHE_FILE)
                print("create whois instance")
                cls._instance = WhoIs(file_loc)
            else:
                raise ValueError("Invalid arguments")
        return cls._instance
            

    def __init__(self, file_loc):

        # A dictionary should probably be fast enough to handle
        # What we do here

        self._cache = {}
        self._file_loc = file_loc

        if not os.path.exists(file_loc):
            print("Cache not found -> start from fresh")
            return

        with open(file_loc) as f:
            for line in f:
                if not line:
                    continue
                addr,json_str = line.strip().split(",", 1)
                json_dict = json.loads(json_str)

                self._cache[addr] = json_dict

    def cleanup(self):
        with open(self._file_loc, "w") as f:
            for key,elt in self._cache.items():
                elt_str = json.dumps(elt)
                f.write(f"{key},{elt_str}\n")
        


    def lookup(self, ipaddr):
        if ipaddr in self._cache:
            return self._cache[ipaddr]

       
        try:
            net = Net(ipaddr)
            obj = IPASN(net)
            result = obj.lookup()
        except Exception as e:
            print(f"exception thrown {e}")
            return None
        self._cache[ipaddr] = result
        return result

     