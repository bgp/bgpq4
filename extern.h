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

struct sx_slentry {
	STAILQ_ENTRY(sx_slentry) entries;
	char*  text;
};

struct sx_slentry* sx_slentry_new(char* text);

struct sx_tentry {
	RB_ENTRY(sx_tentry) entries;
	char* text;
};

struct sx_tentry* sx_tentry_new(char* text);

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
	V_NOKIA_MD,
	V_ARISTA
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
	char		*request;
	int 	 	 size, offset;
	void		*udata;
	unsigned int	 depth;
	int	 	 (*callback)(char *, struct bgpq_expander *,
			    struct bgpq_request *);
};

struct bgpq_expander {
	struct sx_radix_tree	*tree;
	STAILQ_HEAD(sx_slentries, sx_slentry) macroses, rsets;
	RB_HEAD(tentree, sx_tentry) already, stoplist;
	int			 family;
	char			*sources;
	uint32_t		 asnumber;
	int			 aswidth;
	char			*name;
	bgpq_vendor_t		 vendor;
	bgpq_gen_t		 generation;
	int			 identify;
	int			 sequence;
	unsigned int		 maxdepth;
	unsigned int		 cdepth;
	int			 validate_asns;
	unsigned char 		*asn32s[65536];
	struct bgpq_prequest	*firstpipe, *lastpipe;
	int 			 piped;
	char			*match;
	char			*server;
	char			*port;
	char			*format;
	unsigned int		 maxlen;
	STAILQ_HEAD(bgpq_requests, bgpq_request) wq, rq;
	int			 fd;
};

int bgpq_expander_init(struct bgpq_expander *b, int af);
int bgpq_expander_add_asset(struct bgpq_expander *b, char *set);
int bgpq_expander_add_rset(struct bgpq_expander *b, char *set);
int bgpq_expander_add_as(struct bgpq_expander *b, char *as);
int bgpq_expander_add_prefix(struct bgpq_expander *b, char *prefix);
int bgpq_expander_add_prefix_range(struct bgpq_expander *b, char *prefix);
int bgpq_expander_add_stop(struct bgpq_expander *b, char *object);

int bgpq_expand(struct bgpq_expander *b);

int bgpq4_print_prefixlist(FILE *f, struct bgpq_expander *b);
int bgpq4_print_eacl(FILE *f, struct bgpq_expander *b);
int bgpq4_print_aspath(FILE *f, struct bgpq_expander *b);
int bgpq4_print_asset(FILE *f, struct bgpq_expander *b);
int bgpq4_print_oaspath(FILE *f, struct bgpq_expander *b);
int bgpq4_print_route_filter_list(FILE *f, struct bgpq_expander *b);

void sx_radix_node_freeall(struct sx_radix_node *n);
void sx_radix_tree_freeall(struct sx_radix_tree *t);
void bgpq_prequest_freeall(struct bgpq_prequest *bpr);
void expander_freeall(struct bgpq_expander *expander);

/* s - number of opened socket, dir is either SO_SNDBUF or SO_RCVBUF */
int sx_maxsockbuf(int s, int dir);

#ifndef HAVE_STRLCPY
size_t strlcpy(char* dst, const char* src, size_t size);
#endif
