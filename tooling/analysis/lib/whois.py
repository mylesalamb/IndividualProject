'''
Convenience wrapper and utils around ipwhois

We cache results here to help prevent throttling from the registries,
some inparticular are rather nasty with this. Hence caching is essential
'''
import os
import json
import redis
from ipwhois.net import Net
from ipwhois.asn import IPASN

WHOIS_CACHE_FILE = "cache.whois"
REDIS_HOST="localhost"
REDIS_PORT=6379


class WhoIs:

    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance == None:
            cls._instance = WhoIs()
        return cls._instance
            

    def __init__(self):
        self._conn = redis.Redis(REDIS_HOST, port=REDIS_PORT)

    def lookup(self, ipaddr):

        val = self._conn.get(ipaddr)
        if val:
            return json.loads(val)

        try:
            net = Net(ipaddr)
            obj = IPASN(net)
            result = obj.lookup()
        except Exception as e:
            result = {"asn":"private"}
        self._conn.setnx(ipaddr, json.dumps(result))
        return result

     