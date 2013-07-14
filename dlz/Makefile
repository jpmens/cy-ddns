# for building the dlz_myip driver we don't use
# the bind9 build structure as the aim is to provide an
# example that is separable from the bind9 source tree

# this means this Makefile is not portable, so the testsuite
# skips this test on platforms where it doesn't build

CFLAGS=-fPIC -Wall 

all: dlz_myip.so

dlz_myip.so: dlz_myip.o
	$(CC) $(CFLAGS) -shared -o dlz_myip.so dlz_myip.o

clean:
	rm -f dlz_myip.o dlz_myip.so 
