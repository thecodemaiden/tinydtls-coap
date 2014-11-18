tinydtls-coap
=============

An attempt to integrate the libcoap (http://libcoap.sourceforge.net/) and tinydtls (http://tinydtls.sourceforge.net/) client-server examples.

This example is built against (modified) libcoap 4.1.1 and tinyDTLS 0.4.0. They are included as submodules, and can be built in the usual
way (`./configure` then `make`). Because they contain many similar name definitions and header names, it is also assumed
 that the libcoap headers are in `$INCLUDE_DIR/coap`, and the tinydtls headers are in `$INCLUDE_DIR/dtls` (see the Makefile). You should also
change `LIB_DIR` to the location of the built libraries for libcoap and tinyDTLS.     

