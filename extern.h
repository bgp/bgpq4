/*
 * Copyright (c) 2007-2019 Alexandre Snarskii <snar@snar.spb.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/queue.h>
#include <sys/tree.h>

#include "sx_prefix.h"

struct slentry {
	STAILQ_ENTRY(slentry)	 entry;
	char			*text;
};

struct slentry		*sx_slentry_new(char *text);

struct sx_tentry {
	RB_ENTRY(sx_tentry)	 entry;
	char			*text;
};

struct sx_tentry	*sx_tentry_new(char *text);

struct asn_entry {
	RB_ENTRY(asn_entry)	entry;
	uint32_t		asn;
};

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
	V_HUAWEI_XPL,
	V_MIKROTIK6,
	V_MIKROTIK7,
	V_NOKIA_MD,
	V_ARISTA
} bgpq_vendor_t;

typedef enum {
	T_NONE = 0,
	T_ASPATH,
	T_OASPATH,
	T_ASLIST,
	T_ASSET,
	T_PREFIXLIST,	
	T_EACL,
	T_ROUTE_FILTER_LIST
} bgpq_gen_t;

struct bgpq_expander;

struct request {
	STAILQ_ENTRY(request)	 next;
	char			*request;
	int 	 	 	 size, offset;
	void			*udata;
	unsigned int	 	 depth;
	int	 	 	 (*callback)(char *, struct bgpq_expander *,
				    struct request *);
};

struct bgpq_expander {
	struct sx_radix_tree	 	*tree;
	int			 	 family;
	char				*sources;
	char				*defaultsources;
	unsigned int			 usesource;
	uint32_t		 	 asnumber;
	int			 	 aswidth;
	char				*name;
	bgpq_vendor_t		 	 vendor;
	bgpq_gen_t		 	 generation;
	int			 	 identify;
	int			 	 sequence;
	unsigned int		 	 maxdepth;
	unsigned int		 	 cdepth;
	int			 	 validate_asns;
	struct bgpq_prequest		*firstpipe, *lastpipe;
	int 			 	 piped;
	char				*match;
	char				*server;
	char				*port;
	char				*format;
	unsigned int		 	 maxlen;
	int			 	 fd;
	RB_HEAD(asn_tree, asn_entry)	 asnlist;
	STAILQ_HEAD(requests, request)	 wq, rq;
	STAILQ_HEAD(slentries, slentry)	 macroses, rsets;
	RB_HEAD(tentree, sx_tentry)	 already, stoplist;
};

int asn_cmp(struct asn_entry *, struct asn_entry *);
RB_PROTOTYPE(asn_tree, asn_entry, entry, asn_cmp);

int bgpq_expander_init(struct bgpq_expander *b, int af);
int bgpq_expander_add_asset(struct bgpq_expander *b, char *set);
int bgpq_expander_add_rset(struct bgpq_expander *b, char *set);
int bgpq_expander_add_as(struct bgpq_expander *b, char *as);
int bgpq_expander_add_prefix(struct bgpq_expander *b, char *prefix);
int bgpq_expander_add_prefix_range(struct bgpq_expander *b, char *prefix);
int bgpq_expander_add_stop(struct bgpq_expander *b, char *object);

char* bgpq_get_asset(char *object);
char* bgpq_get_rset(char *object);
char* bgpq_get_source(char *object);

int bgpq_expand(struct bgpq_expander *b);

void bgpq4_print_prefixlist(FILE *f, struct bgpq_expander *b);
void bgpq4_print_eacl(FILE *f, struct bgpq_expander *b);
void bgpq4_print_aspath(FILE *f, struct bgpq_expander *b);
void bgpq4_print_asset(FILE *f, struct bgpq_expander *b);
void bgpq4_print_oaspath(FILE *f, struct bgpq_expander *b);
void bgpq4_print_aslist(FILE *f, struct bgpq_expander *b);
void bgpq4_print_route_filter_list(FILE *f, struct bgpq_expander *b);

void sx_radix_node_freeall(struct sx_radix_node *n);
void sx_radix_tree_freeall(struct sx_radix_tree *t);
void bgpq_prequest_freeall(struct bgpq_prequest *bpr);
void expander_freeall(struct bgpq_expander *expander);

/* s - number of opened socket, dir is either SO_SNDBUF or SO_RCVBUF */
int sx_maxsockbuf(int s, int dir);

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif
