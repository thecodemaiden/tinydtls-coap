// Copyright (C) 2014 Regents of the University of California.
// Author: Adeola Bannis <thecodemaiden@gmail.com>
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// A copy of the GNU General Public License is in the file COPYING.
//
// Modified from server.c (libcoap) and dtls-server.c (tinydtls)
// Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>
//
#define __APPLE_USE_RFC_2292
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <syslog.h>

#include "coap/config.h"
#include "coap/resource.h"
#include "coap/coap.h"
#include "coap/address.h"
#include "coap/net.h"

#define COAP_RESOURCE_CHECK_TIME 2

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif
#include "dtls/config.h" 
#include "dtls/dtls.h" 
#include "dtls/debug.h" 

#define DEFAULT_PORT 20220

#define INDEX "This is a combination of libcoap's and tinydtl's server implementations.\n"

// TODO: convert this mess into C++!

/* temporary storage for dynamic resource representations */
static int quit = 0;

/* changeable clock base (see handle_put_time()) */
static time_t my_clock_base = 0;

struct coap_resource_t *time_resource = NULL;

typedef struct {
    int *fd;
    coap_context_t *coap_context;
} coaps_context_t;

// ugly, but what else can I do? I need this inside coap functions
// TODO: add a global coaps context
//struct coap_context_t *
struct dtls_context_t *globalCtx = NULL;

#ifndef WITHOUT_ASYNC
/* This variable is used to mimic long-running tasks that require
 * asynchronous responses. */
static coap_async_state_t *async = NULL;
#endif /* WITHOUT_ASYNC */

extern size_t dsrv_print_addr(const session_t *, unsigned char *, size_t);
/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  quit = 1;
}

static coaps_context_t sec_ctx = {
    .fd = 0,
    .coap_context = NULL
};


void 
hnd_get_index(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, str *token,
	      coap_pdu_t *response) {
  unsigned char buf[3];

  response->hdr->code = COAP_RESPONSE_CODE(205);

  coap_add_option(response, COAP_OPTION_CONTENT_TYPE,
	  coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);

  coap_add_option(response, COAP_OPTION_MAXAGE,
	  coap_encode_var_bytes(buf, 0x2ffff), buf);
    
  coap_add_data(response, strlen(INDEX), (unsigned char *)INDEX);
}

void 
hnd_get_time(coap_context_t  *ctx, struct coap_resource_t *resource, 
	     coap_address_t *peer, coap_pdu_t *request, str *token,
	     coap_pdu_t *response) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  unsigned char buf[40];
  size_t len;
  time_t now;
  coap_tick_t t;
  coap_subscription_t *subscription;

  /* FIXME: return time, e.g. in human-readable by default and ticks
   * when query ?ticks is given. */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  response->hdr->code = 
    my_clock_base ? COAP_RESPONSE_CODE(205) : COAP_RESPONSE_CODE(404);

  if (request != NULL &&
      coap_check_option(request, COAP_OPTION_OBSERVE, &opt_iter)) {
    subscription = coap_add_observer(resource, peer, token);
    if (subscription) {
      subscription->non = request->hdr->type == COAP_MESSAGE_NON;
      coap_add_option(response, COAP_OPTION_OBSERVE, 0, NULL);
    }
  }
  if (resource->dirty == 1)
    coap_add_option(response, COAP_OPTION_OBSERVE, 
		    coap_encode_var_bytes(buf, ctx->observe), buf);

    
  if (my_clock_base)
    coap_add_option(response, COAP_OPTION_CONTENT_FORMAT,
		    coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);

  coap_add_option(response, COAP_OPTION_MAXAGE,
	  coap_encode_var_bytes(buf, 0x01), buf);

  if (my_clock_base) {

    /* calculate current time */
    coap_ticks(&t);
    now = my_clock_base + (t / COAP_TICKS_PER_SECOND);
    
    if (request != NULL
	&& (option = coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter))
	&& memcmp(COAP_OPT_VALUE(option), "ticks",
		  min(5, COAP_OPT_LENGTH(option))) == 0) {
      /* output ticks */
      len = snprintf((char *)buf, 
	   min(sizeof(buf), response->max_size - response->length),
		     "%u", (unsigned int)now);
      coap_add_data(response, len, buf);

    } else {			/* output human-readable time */
      struct tm *tmp;
      tmp = gmtime(&now);
      len = strftime((char *)buf, 
		     min(sizeof(buf), response->max_size - response->length),
		     "%b %d %H:%M:%S", tmp);
      coap_add_data(response, len, buf);
    }
  }
}

void 
hnd_put_time(coap_context_t  *ctx, struct coap_resource_t *resource, 
	     coap_address_t *peer, coap_pdu_t *request, str *token,
	     coap_pdu_t *response) {
  coap_tick_t t;
  size_t size;
  unsigned char *data;

  /* FIXME: re-set my_clock_base to clock_offset if my_clock_base == 0
   * and request is empty. When not empty, set to value in request payload
   * (insist on query ?ticks). Return Created or Ok.
   */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  response->hdr->code = 
    my_clock_base ? COAP_RESPONSE_CODE(204) : COAP_RESPONSE_CODE(201);

  resource->dirty = 1;

  coap_get_data(request, &size, &data);
  
  if (size == 0)		/* re-init */
    my_clock_base = clock_offset;
  else {
    my_clock_base = 0;
    coap_ticks(&t);
    while(size--) 
      my_clock_base = my_clock_base * 10 + *data++;
    my_clock_base -= t / COAP_TICKS_PER_SECOND;
  }
}

void 
hnd_delete_time(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, str *token,
	      coap_pdu_t *response) {
  my_clock_base = 0;		/* mark clock as "deleted" */
  
  /* type = request->hdr->type == COAP_MESSAGE_CON  */
  /*   ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON; */
}

#ifndef WITHOUT_ASYNC
void 
hnd_get_async(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, str *token,
	      coap_pdu_t *response) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  unsigned long delay = 5;
  size_t size;

  if (async) {
    if (async->id != request->hdr->id) {
      coap_opt_filter_t f;
      coap_option_filter_clear(f);
      response->hdr->code = COAP_RESPONSE_CODE(503);
    }
    return;
  }

  option = coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter);
  if (option) {
    unsigned char *p = COAP_OPT_VALUE(option);

    delay = 0;
    for (size = COAP_OPT_LENGTH(option); size; --size, ++p)
      delay = delay * 10 + (*p - '0');
  }

  async = coap_register_async(ctx, peer, request, 
			      COAP_ASYNC_SEPARATE | COAP_ASYNC_CONFIRM,
			      (void *)(COAP_TICKS_PER_SECOND * delay));
}

void 
check_async(coap_context_t  *ctx, coap_tick_t now) {
  coap_pdu_t *response;
  coap_async_state_t *tmp;

  size_t size = sizeof(coap_hdr_t) + 8;

  if (!async || now < async->created + (unsigned long)async->appdata) 
    return;

  response = coap_pdu_init(async->flags & COAP_ASYNC_CONFIRM 
			   ? COAP_MESSAGE_CON
			   : COAP_MESSAGE_NON,
			   COAP_RESPONSE_CODE(205), 0, size);
  if (!response) {
    debug("check_async: insufficient memory, we'll try later\n");
    async->appdata = 
      (void *)((unsigned long)async->appdata + 15 * COAP_TICKS_PER_SECOND);
    return;
  }
  
  response->hdr->id = coap_new_message_id(ctx);

  if (async->tokenlen)
    coap_add_token(response, async->tokenlen, async->token);

  coap_add_data(response, 4, (unsigned char *)"done");

  if (coap_send(ctx, &async->peer, response) == COAP_INVALID_TID) {
    debug("check_async: cannot send response for message %d\n", 
	  response->hdr->id);
  }
  coap_delete_pdu(response);
  coap_remove_async(ctx, async->id, &tmp);
  coap_free_async(async);
  async = NULL;
}
#endif /* WITHOUT_ASYNC */

void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(NULL, 0, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
  coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"General Info\"", 14, 0);
  coap_add_resource(ctx, r);

  /* store clock base to use in /time */
  my_clock_base = clock_offset;

  r = coap_resource_init((unsigned char *)"time", 4, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
  coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"Internal Clock\"", 16, 0);
  coap_add_attr(r, (unsigned char *)"rt", 2, (unsigned char *)"\"Ticks\"", 7, 0);
  r->observable = 1;
  coap_add_attr(r, (unsigned char *)"if", 2, (unsigned char *)"\"clock\"", 7, 0);

  coap_add_resource(ctx, r);
  time_resource = r;

#ifndef WITHOUT_ASYNC
  r = coap_resource_init((unsigned char *)"async", 5, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
  coap_add_resource(ctx, r);
#endif /* WITHOUT_ASYNC */
}

void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
	   "(c) 2010,2011 Olaf Bergmann <bergmann@tzi.org>\n\n"
	   "usage: %s [-A address] [-p port]\n\n"
	   "\t-A address\tinterface address to bind to\n"
	   "\t-p port\t\tlisten on specified port\n"
	   "\t-v num\t\tverbosity level (default: 3)\n",
	   program, version, program );
}

coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;  
  int s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
  
  s = getaddrinfo(node, port, &hints, &result);
  if ( s != 0 ) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return NULL;
  } 

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    coap_address_t addr;

    if (rp->ai_addrlen <= sizeof(addr.addr)) {
      coap_address_init(&addr);
      addr.size = rp->ai_addrlen;
      memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);

      ctx = coap_new_context(&addr);
      if (ctx) {
	/* TODO: output address:port for successful binding */
	goto finish;
      }
    }
  }
  
  fprintf(stderr, "no context available for interface '%s'\n", node);

 finish:
  freeaddrinfo(result);
  return ctx;
}


#if 0
/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  dsrv_stop(dsrv_get_context());
}
#endif

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
int
get_key(struct dtls_context_t *ctx, 
	const session_t *session, 
	const unsigned char *id, size_t id_len, 
	const dtls_key_t **result) {

  static const dtls_key_t psk = {
    .type = DTLS_KEY_PSK,
    .key.psk.id = (unsigned char *)"Client_identity", 
    .key.psk.id_length = 15,
    .key.psk.key = (unsigned char *)"secretPSK", 
    .key.psk.key_length = 9
  };
   
  *result = &psk;
  return 0;
}

int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {

    coap_address_t srcAddr;
    coap_context_t *coap_ctx = ((coaps_context_t *)dtls_get_app_data(ctx))->coap_context;

    memcpy(&(srcAddr.addr), &(session->addr), session->size);
    srcAddr.size = session->size;
    
   return coap_read_from_buf(data, len, coap_ctx, &srcAddr);
}


coap_tid_t coaps_send_handler(coap_context_t *ctx, const coap_address_t *dst, coap_pdu_t *pdu)
{

// TODO: get a global ref to the dtls_context... :'(
   // HACK: making the session ourselves
    session_t fakeSession;

    dtls_session_init(&fakeSession);
    memcpy(&(fakeSession.addr), &(dst->addr), dst->size);
    fakeSession.size = dst->size;
    fakeSession.ifindex = *(sec_ctx.fd);

    coap_tid_t id = COAP_INVALID_TID;
    uint8 buf[COAP_MAX_PDU_SIZE];
    memcpy(buf, pdu->hdr, pdu->length);
    int bytes_written = dtls_write(globalCtx, &fakeSession, buf, pdu->length);
    if (bytes_written > 0) {
      coap_transaction_id(dst, pdu, &id);
    } else {
      coap_log(LOG_CRIT, "coap_send: sendto\n");
    }
    return id;
}


int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  int fd = *((coaps_context_t *)dtls_get_app_data(ctx))->fd;
  return sendto(fd, data, len, MSG_DONTWAIT,
		&session->addr.sa, session->size);
}

int
dtls_handle_read(struct dtls_context_t *ctx) {
  int *fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  fd = ((coaps_context_t *)dtls_get_app_data(ctx))->fd;

  assert(fd);

  dtls_session_init(&session);
  session.size = sizeof(session.addr);
  session.ifindex = *fd;
  len = recvfrom(*fd, buf, sizeof(buf), 0, 
		 &session.addr.sa, &session.size);
  
  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dsrv_log(LOG_DEBUG, "got %d bytes from port %d\n", len, 
	     ntohs(session.addr.sin6.sin6_port));
  }

  return dtls_handle_message(ctx, &session, buf, len);
}    

int 
resolve_address(const char *server, struct sockaddr *dst) {
  
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;

  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET6:

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;
}

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
  .get_key = get_key
};

int 
main(int argc, char **argv) {
  log_t log_level = LOG_WARNING;
  fd_set rfds, wfds;
  struct timeval tv,  *timeout;
  int fd, opt, result;
  int on = 1;
  struct sockaddr_in6 listen_addr;
  coap_tick_t now;
  coap_queue_t *nextpdu;

  coap_context_t *ctx;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = "5683";

  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));

  /* fill extra field for 4.4BSD-based systems (see RFC 3493, section 3.4) */
#if defined(SIN6_LEN) || defined(HAVE_SOCKADDR_IN6_SIN6_LEN)
  listen_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif

  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_port = htons(DEFAULT_PORT);
  listen_addr.sin6_addr = in6addr_any;

  while ((opt = getopt(argc, argv, "A:p:v:")) != -1) {
    switch (opt) {
    case 'A' :
      if (resolve_address(optarg, (struct sockaddr *)&listen_addr) < 0) {
        fprintf(stderr, "cannot resolve address\n");
        exit(-1);
      } else {
          strncpy(addr_str, optarg, NI_MAXHOST-1);
          addr_str[NI_MAXHOST - 1] = '\0';
      }
      break;
    case 'p' :
      listen_addr.sin6_port = htons(atoi(optarg));
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage(argv[0], PACKAGE_VERSION);
      exit(1);
    }
  }

  coap_set_send_handler(&coaps_send_handler);
  dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

  init_resources(ctx);

  /* init socket and set it to non-blocking */
  //fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);
  fd = ctx->sockfd;
  if (fd < 0) {
    dsrv_log(LOG_ALERT, "socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }

  on = 1;
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
    dsrv_log(LOG_ALERT, "setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
  }

  /*
  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    dsrv_log(LOG_ALERT, "bind: %s\n", strerror(errno));
    goto error;
  }
*/
  dtls_init();

  sec_ctx.fd = &fd;
  sec_ctx.coap_context = ctx;

  globalCtx = dtls_new_context(&sec_ctx);

  dtls_set_handler(globalCtx, &cb);

  while (1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fd, &rfds);

    nextpdu = coap_peek_next( ctx );
    coap_ticks(&now);
    while (nextpdu && nextpdu->t <= now - ctx->sendqueue_basetime) {
      coap_retransmit( ctx, coap_pop_next( ctx ) );
      nextpdu = coap_peek_next( ctx );
    }

    if ( nextpdu && nextpdu->t <= COAP_RESOURCE_CHECK_TIME ) {
      /* set timeout if there is a pdu to send before our automatic timeout occurs */
      tv.tv_usec = ((nextpdu->t) % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
      tv.tv_sec = (nextpdu->t) / COAP_TICKS_PER_SECOND;
      timeout = &tv;
    } else {
      tv.tv_usec = 0;
      tv.tv_sec = COAP_RESOURCE_CHECK_TIME;
      timeout = &tv;
    }

    result = select( fd+1, &rfds, &wfds, 0, timeout);
    
    if (result < 0) {		/* error */
      if (errno != EINTR)
	perror("select");
    } else if (result == 0) {	/* timeout */
    } else {			/* ok */
      if (FD_ISSET(fd, &wfds))
	; //?
      else if (FD_ISSET(fd, &rfds)) {
	dtls_handle_read(globalCtx);
    // TODO: ADD THE DTLS READY EVENT! 
    coap_dispatch(ctx);
      }
    }
#ifndef WITHOUT_ASYNC
    /* check if we have to send asynchronous responses */
    check_async(ctx, now);
#endif /* WITHOUT_ASYNC */

#ifndef WITHOUT_OBSERVE
    /* check if we have to send observe notifications */
    coap_check_notify(ctx);
#endif /* WITHOUT_OBSERVE */
  }
  
 error:
  dsrv_log(LOG_DEBUG, "Freeing contexts");
  dtls_free_context(globalCtx);
  coap_free_context(ctx);
  exit(0);
}
