tinydtls-coap
=============

An attempt to integrate the libcoap (http://libcoap.sourceforge.net/) and tinydtls (http://tinydtls.sourceforge.net/) client-server examples.

In order to make this, it is assumed you have successfully compiled both libcoap and tinydtls. Because they contain many similar name definitions, it is also assumed that the libcoap headers are in $INCLUDE_DIR/coap, and the tinydtls headers are in $INCLUDE_DIR/dtls.

Then, change INCLUDE_DIR and LIB_DIR in the Makefile to the location of the headers and libraries, respectively, and run `make`.
