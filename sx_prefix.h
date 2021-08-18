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

#ifndef _SX_PREFIX_H_
#define _SX_PREFIX_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct sx_prefix { 
	int family; 
	unsigned int masklen; 
	union { 
		struct in_addr  addr; 
		struct in6_addr addr6; 
		unsigned char   addrs[sizeof(struct in6_addr)];
	} addr;
} sx_prefix_t;

typedef struct sx_radix_node { 
	struct sx_radix_node	*parent, *l, *r, *son;
	void			*payload;
	unsigned int 		 isGlue:1;
	unsigned int 		 isAggregated:1;
	unsigned int 		 isAggregate:1;
	unsigned int 		 aggregateLow;
	unsigned int 		 aggregateHi;
	struct sx_prefix	*prefix;
} sx_radix_node_t;

typedef struct sx_radix_tree { 
	int 			 family;
	struct sx_radix_node	*head;
} sx_radix_tree_t;

/* most common operations with the tree is to: lookup/insert/unlink */
struct sx_radix_node *sx_radix_tree_lookup(struct sx_radix_tree *tree,
    struct sx_prefix *prefix);
struct sx_radix_node *sx_radix_tree_insert(struct sx_radix_tree *tree, 
    struct sx_prefix *prefix);
void sx_radix_tree_unlink(struct sx_radix_tree *t, struct sx_radix_node *n);
struct sx_radix_node *sx_radix_tree_lookup_exact(struct sx_radix_tree *tree,
	struct sx_prefix *prefix);

struct sx_prefix *sx_prefix_alloc(struct sx_prefix *p);
void sx_prefix_destroy(struct sx_prefix *p);
void sx_radix_node_destroy(struct sx_radix_node *p);
void sx_prefix_adjust_masklen(struct sx_prefix *p);
struct sx_prefix *sx_prefix_new(int af, char *text);
int sx_prefix_parse(struct sx_prefix *p, int af, char *text);
int sx_prefix_range_parse(struct sx_radix_tree *t, int af, unsigned int ml, char *text);
int sx_prefix_fprint(FILE *f, struct sx_prefix *p);
int sx_prefix_snprintf(struct sx_prefix *p, char *rbuffer, int srb);
int sx_prefix_snprintf_sep(struct sx_prefix *p, char *rbuffer, int srb, char *);
void sx_prefix_snprintf_fmt(struct sx_prefix *p, FILE *f,
    const char *name, const char *fmt, unsigned int aggregateLow,
    unsigned int aggregateHi);
int sx_prefix_jsnprintf(struct sx_prefix *p, char *rbuffer, int srb);
struct sx_radix_tree *sx_radix_tree_new(int af);
struct sx_radix_node *sx_radix_node_new(struct sx_prefix *prefix);
struct sx_prefix *sx_prefix_overlay(struct sx_prefix *p, int n);
int sx_radix_tree_empty(struct sx_radix_tree *t);
void sx_radix_node_fprintf(struct sx_radix_node *node, void *udata);
int  sx_radix_node_foreach(struct sx_radix_node *node, 
	void (*func)(struct sx_radix_node *, void *), void *udata);
int sx_radix_tree_foreach(struct sx_radix_tree *tree, 
	void (*func)(struct sx_radix_node *, void *), void *udata);
int sx_radix_tree_aggregate(struct sx_radix_tree *tree);
int sx_radix_tree_refine(struct sx_radix_tree *tree, unsigned refine);
int sx_radix_tree_refineLow(struct sx_radix_tree *tree, unsigned refineLow);

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#endif
