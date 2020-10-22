EXEC=ecnDetector
EXECSOURCES= netinject.o connector.o pcapture.o driver.o parser.o
CC=gcc
CFLAGS=-O2 -Wall
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean rmd cleanall

clean:
	rm $(EXECSOURCES) $(EXEC)
rmd:
	rm *.pcap

cleanall: clean rmd
