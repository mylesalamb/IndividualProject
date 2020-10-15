EXEC=ecnDetector
EXECSOURCES= netinject.o connector.o pcapture.o driver.o
CC=gcc
CFLAGS=-O2 -g -Wall
LDLIBS=-lpcap -lpthread

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean

clean:
	rm $(EXECSOURCES) $(EXEC)
