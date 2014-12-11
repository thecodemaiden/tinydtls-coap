
CFLAGS:=-Wall -g -O0
LDFLAGS:=-L./coap -L./dtls


SOURCES:= coaps-client.c  coaps-server.c
PROGRAMS:= $(patsubst %.c, %, $(SOURCES))

all:	$(PROGRAMS)

coaps-server.o:	coaps-server.c
	$(CC) -c  $(CFLAGS)  -o $@ $< -DDTLSv12 -DWITH_SHA256 -DWITH_POSIX 

coaps-server: coaps-server.o
	$(CC) -o $@ $< $(LDFLAGS) -lcoap -ltinydtls

coaps-client: coaps-client.o 
	$(CC) -o $@ $< $(LDFLAGS) -lcoap -ltinydtls

coaps-client.o:	coaps-client.c
	$(CC) -c $(CFLAGS)  -o $@ $< -DDTLSv12 -DWITH_SHA256 -DWITH_POSIX 
 
clean:
	@rm -f $(PROGRAMS) *.o
