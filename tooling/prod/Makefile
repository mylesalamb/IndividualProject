EXEC=ecnDetector
EXECSOURCES= netinject.o connector.o pcapture.o driver.o
CC=gcc
CFLAGS=-O2 -g -Wall
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean

clean:
	rm $(EXECSOURCES) $(EXEC)
