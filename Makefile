INCLUDE_DIR:=/Users/abannis/REMAP/coap/inc
LIB_DIR:=/Users/abannis/REMAP/coap/lib

CFLAGS:=-Wall -g -O2
LDFLAGS:=-L$(LIB_DIR)


SOURCES:= coap-server.c dtls-server.c coap-client.c dtls-client.c coaps-server.c
PROGRAMS:= $(patsubst %.c, %, $(SOURCES))

all:	$(PROGRAMS)

coap-client: coap-client.o 
	$(CC) -o $@ $< $(LDFLAGS) -lcoap

coap-client.o:	coap-client.c
	$(CC) -c -I$(INCLUDE_DIR) -o $@ $< -DWITH_POSIX

dtls-client.o:	dtls-client.c
	$(CC) -c -I$(INCLUDE_DIR) -o $@ $< -DDTLSv12 -DWITH_SHA256

dtls-client: dtls-client.o
	$(CC) -o $@ $< $(LDFLAGS) -ltinydtls

coap-server: coap-server.o 
	$(CC) -o $@ $< $(LDFLAGS) -lcoap

coap-server.o:	coap-server.c
	$(CC) -c -I$(INCLUDE_DIR) -o $@ $< -DWITH_POSIX

dtls-server.o:	dtls-server.c
	$(CC) -c -I$(INCLUDE_DIR) -o $@ $< -DDTLSv12 -DWITH_SHA256

dtls-server: dtls-server.o
	$(CC) -o $@ $< $(LDFLAGS) -ltinydtls

coaps-server.o:	coaps-server.c
	$(CC) -c -I$(INCLUDE_DIR) -o $@ $< -DDTLSv12 -DWITH_SHA256 -DWITH_POSIX 

coaps-server: coaps-server.o
	$(CC) -o $@ $< $(LDFLAGS) -lcoap -ltinydtls

clean:
	@rm -f $(PROGRAMS) *.o
