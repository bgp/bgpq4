#ifndef BGPQ4_H_
#define BGPQ4_H_

#if HAVE_SYS_QUEUE_H && HAVE_STAILQ_IN_SYS_QUEUE
#include <sys/queue.h>
#else
#include "sys_queue.h"
#endif

#include "sx_prefix.h"
#include "sx_slentry.h"

typedef enum {
	V_CISCO = 0,
	V_JUNIPER,
	V_CISCO_XR,
	V_JSON,
	V_BIRD,
	V_OPENBGPD,
	V_FORMAT,
	V_NOKIA,
	V_HUAWEI,
	V_MIKROTIK,
	V_NOKIA_MD
} bgpq_vendor_t;

typedef enum {
	T_NONE = 0,
	T_ASPATH,
	T_OASPATH,
	T_ASSET,
	T_PREFIXLIST,	
	T_EACL,
	T_ROUTE_FILTER_LIST
} bgpq_gen_t;

struct bgpq_expander;

struct bgpq_request {
	STAILQ_ENTRY(bgpq_request) next;
	char* request;
	int size, offset;
	int (*callback)(char*, struct bgpq_expander*, struct bgpq_request*);
	void *udata;
	unsigned depth;
};

struct bgpq_expander {
	struct sx_radix_tree* tree;
	STAILQ_HEAD(sx_slentries, sx_slentry) macroses, rsets;
	RB_HEAD(tentree, sx_tentry) already, stoplist;
	int family;
	char* sources;
	uint32_t asnumber;
	int aswidth;
	char* name;
	bgpq_vendor_t vendor;
	bgpq_gen_t    generation;
	int identify;
	int sequence;
	int maxdepth;
	int validate_asns;
	unsigned char asn32;
	unsigned char* asn32s[65536];
	struct bgpq_prequest* firstpipe, *lastpipe;
	int piped;
	char* match;
	char* server;
	char* port;
	char* format;
	unsigned maxlen;
	STAILQ_HEAD(bgpq_requests, bgpq_request) wq, rq;
	int fd, cdepth;
};


int bgpq_expander_init(struct bgpq_expander* b, int af);
int bgpq_expander_add_asset(struct bgpq_expander* b, char* set);
int bgpq_expander_add_rset(struct bgpq_expander* b, char* set);
int bgpq_expander_add_as(struct bgpq_expander* b, char* as);
int bgpq_expander_add_prefix(struct bgpq_expander* b, char* prefix);
int bgpq_expander_add_prefix_range(struct bgpq_expander* b, char* prefix);
int bgpq_expander_add_stop(struct bgpq_expander* b, char* object);

int bgpq_expand(struct bgpq_expander* b);

int bgpq4_print_prefixlist(FILE* f, struct bgpq_expander* b);
int bgpq4_print_eacl(FILE* f, struct bgpq_expander* b);
int bgpq4_print_aspath(FILE* f, struct bgpq_expander* b);
int bgpq4_print_asset(FILE* f, struct bgpq_expander* b);
int bgpq4_print_oaspath(FILE* f, struct bgpq_expander* b);
int bgpq4_print_route_filter_list(FILE* f, struct bgpq_expander* b);

#ifndef HAVE_STRLCPY
size_t strlcpy(char* dst, const char* src, size_t size);
#endif

#endif
