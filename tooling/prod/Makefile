EXEC=ecnDetector
EXECSOURCES=connector.o netinject.o connector.o pcapture.o driver.o parser.o
WORK_DIR=$(shell pwd)
CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic -Iboringssl/include -Ilsquic/include -Ilsquic/src/liblsquic
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink -lz -lev -lm -L$(WORK_DIR)/lsquic/src/liblsquic -llsquic \
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
