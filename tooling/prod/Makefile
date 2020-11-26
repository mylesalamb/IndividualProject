# If using rhel, please install libnetfilter from SOURCE (ver > 1.0.5)
# the package fedora 32 ships with is from 2012 and contains a bug
# where checksums assume IPPOROTO_TCP
# UDP checksums are slightly out if you use the repo variant
# and may be rejected by the network

EXEC=ecnDetector
EXECSOURCES=netinject.o connector.o pcapture.o driver.o parser.o
WORK_DIR=$(shell pwd)
CC=gcc
CFLAGS=-O2 -Wall -Wpedantic -Iboringssl/include -Ilsquic/include -Ilsquic/src/liblsquic
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink -lz -lev -lm -llsquic \
		-L$(WORK_DIR)/boringssl/ssl -L$(WORK_DIR)/boringssl/crypto -lssl -lcrypto # link against boringssl defined


$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

debug: CFLAGS += -g
debug: $(EXEC)

.PHONY: clean rmd cleanall test

test: CFLAGS += -DUNIT_TEST
test: $(EXECSOURCES)
	$(MAKE) -C test/

clean:
	-rm $(EXECSOURCES) $(EXEC)
rmd:
	-rm -f data/*.pcap

cleanall: clean rmd
