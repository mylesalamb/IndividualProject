import csv, redis, json
import sys

REDIS_HOST = "localhost"
REDIS_PORT = 6379
DATA_FILE = "cache.whois"


def get_csv_data():
    odata = []
    with open(DATA_FILE) as f:
        for line in f:
            if not line:
                continue
            dev, asn_data = line.strip().split(",", maxsplit=1)
            odata.append((dev, asn_data))

    return odata

def store_data(connection, data):
    for key, val in data:
        connection.setnx(key, val)


def main():
    data = get_csv_data()
    connection = redis.Redis(REDIS_HOST, port=REDIS_PORT)
    store_data(connection, data)

if __name__ == "__main__":
    print("Store csv to redis cache")
    main()