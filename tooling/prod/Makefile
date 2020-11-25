# If using rhel, please install libnetfilter from SOURCE (ver > 1.0.5)
# the package fedora 32 ships with is from 2012 and contains a bug
# where checksums assume IPPOROTO_TCP
# UDP checksums are slightly out if you use the repo variant
# and may be rejected by the network

EXEC=ecnDetector
EXECSOURCES= netinject.o connector.o pcapture.o driver.o parser.o quic.o
CC=clang
CFLAGS=-O2 -Wall -Wpedantic -I/home/myleslamb/boringssl/include -I/home/myleslamb/lsquic/include -I/home/myleslamb/lsquic/src/liblsquic
LDLIBS= -lssl -lcrypto -lz -lpcap -lpthread -lnetfilter_queue -lnfnetlink -lev  -lm -llsquic

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
