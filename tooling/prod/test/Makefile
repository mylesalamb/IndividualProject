# Test module, requires CUnit-[dev,devel] >= 2.1.3-21

EXECSOURCES=test_driver.o
EXEC=test_exec
CC=gcc
CFLAGS=-O2 -Wall -I../
LDLIBS=-lpcap -lpthread -lnetfilter_queue -lnfnetlink -lcunit

.PHONY: $(EXEC) clean

$(EXEC): $(EXECSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
	./$(EXEC)

clean:
	-rm *.o