EXEC=ecnDetector
EXECSOURCES= netinject.o connector.o pcapture.o driver.o
CC=gcc
CFLAGS=-O2 -Wall
LDLIBS=-lpcap -lpthread

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean

clean:
	rm $(EXECSOURCES) $(EXEC)
