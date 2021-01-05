include Makefile.variables

EXEC=ecnDetector
EXECSOURCES=connector.o netinject.o connector.o pcapture.o driver.o parser.o context.o log.o
WORK_DIR=$(shell pwd)
CC=clang
CFLAGS= -Wall -fsigned-char -I$(BSSL_DIR)/include -I$(LSQUIC_DIR)/include -I$(LSQUIC_DIR)/src/liblsquic
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink -lev -llsquic -lz -lm \
		-L$(BSSL_DIR)/ssl -L$(BSSL_DIR)/crypto -lssl -lcrypto # link against boringssl defined


default: CFLAGS += -O2
default: $(EXEC)

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

debug: CFLAGS += -g -O1 -fno-omit-frame-pointer -DDEBUG
debug: $(EXEC)

.PHONY: clean rmd cleanall test

test: CFLAGS += -DUNIT_TEST
test: $(EXECSOURCES)
	$(MAKE) -C test/ CFLAGS="$(CFLAGS) -I$(shell pwd)" LDLIBS="$(LDLIBS)" CC="$(CC)"

clean:
	-rm $(EXECSOURCES) $(EXEC)
rmd:
	-rm -f data/*.pcap

cleanall: clean rmd
