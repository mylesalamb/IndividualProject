# Test module, requires CUnit-[dev,devel] >= 2.1.3-21
include ../Makefile.variables

EXECSOURCES=test_driver.o
TESTSOURCES= $(shell ls ../*.o | grep -v driver.o)
EXEC=test_exec

$(EXEC): $(EXECSOURCES) $(TESTSOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lcunit
	./$(EXEC)

.PHONY: clean

clean:
	-rm *.o