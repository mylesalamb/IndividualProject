# If using rhel, please install libnetfilter from SOURCE (ver > 1.0.5)
# the package fedora 32 ships with is from 2012 and contains a bug
# where checksums assume IPPOROTO_TCP
# UDP checksums are slightly out if you use the repo variant
# and may be rejected by the network

EXEC=ecnDetector
EXECSOURCES= netinject.o connector.o pcapture.o driver.o parser.o
CC=gcc
CFLAGS=-O2 -g -Wall
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink 
# LDPATH=-L/usr/local/lib

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDPATH) $(LDLIBS)

.PHONY: clean rmd cleanall

clean:
	-rm $(EXECSOURCES) $(EXEC)
rmd:
	-rm -f data/*.pcap

cleanall: clean rmd
