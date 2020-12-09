EXEC=ecnDetector
EXECSOURCES=connector.o netinject.o connector.o pcapture.o driver.o parser.o context.o log.o
WORK_DIR=$(shell pwd)
CC=clang
CFLAGS= -Wall -Iboringssl/include -Ilsquic/include -Ilsquic/src/liblsquic
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink -lev -llsquic -lz -lm \
		-L$(WORK_DIR)/boringssl/ssl -L$(WORK_DIR)/boringssl/crypto -lssl -lcrypto # link against boringssl defined


default: CFLAGS += -O2
default: $(EXEC)

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

debug: CFLAGS += -g -O1 -fno-omit-frame-pointer
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
