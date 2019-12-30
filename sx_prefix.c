#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "sx_prefix.h"
#include "sx_report.h"

int debug_aggregation=0;
extern int debug_expander;

struct sx_prefix*
sx_prefix_alloc(struct sx_prefix* p)
{
	struct sx_prefix* sp = malloc(sizeof(struct sx_prefix));

	if (!sp)
		return NULL;

	if (p)
		memcpy(sp, p, sizeof(struct sx_prefix));
	else
		memset(sp, 0, sizeof(struct sx_prefix));

	return sp;
};

void
sx_prefix_destroy(struct sx_prefix* p)
{
	if (p)
		free(p);
};

void
sx_radix_node_destroy(struct sx_radix_node *n)
{
	if (n) {
		if (n->payload)
			free(n->payload);

    		if (n->prefix)
			free(n->prefix);

    		free(n);
	}
};

void
sx_prefix_adjust_masklen(struct sx_prefix* p)
{
	int nbytes = (p->family == AF_INET ? 4 : 16);
	int i;

	if (p->masklen == nbytes * 8)
		return; /* mask is all ones */

	for (i = nbytes -1; i > p->masklen / 8; i--) {
		p->addr.addrs[i]=0;
	};

	for (i = 1; i <= 8 - p->masklen % 8; i++) {
		p->addr.addrs[p->masklen / 8] &= (0xff << i);
	};
};

void
sx_prefix_mask(struct sx_prefix* p, struct sx_prefix* q)
{
	int i;

	memset(q->addr.addrs, 0, sizeof(q->addr.addrs));

	q->family = p->family;
	q->masklen = p->masklen;

	for (i = 0; i < p->masklen / 8; i++)
		q->addr.addrs[i] = 0xff;

	for (i = 1; i <= p->masklen % 8; i++)
		q->addr.addrs[p->masklen / 8] |= (1 << (8 - i));
};

void
sx_prefix_imask(struct sx_prefix* p, struct sx_prefix* q)
{
	int i;

	memset(q->addr.addrs, 0xff, sizeof(q->addr.addrs));

	q->family = p->family;
	q->masklen = p->masklen;

	for (i = 0; i < p->masklen / 8; i++)
		q->addr.addrs[i] = 0;

	for (i = 1;i <= p->masklen % 8; i++)
		q->addr.addrs[p->masklen / 8] &= ~(1 <<(8 - i));
};


int
sx_prefix_parse(struct sx_prefix* p, int af, char* text)
{
	char* c = NULL;
	int masklen, ret;
	char mtext[INET6_ADDRSTRLEN+5];

	strlcpy(mtext, text, sizeof(mtext));

	c = strchr(mtext,'/');

	if (c) {
		char* eod;
		*c = 0;
		masklen = strtol(c+1, &eod, 10);
		if (eod && eod[0] && !isspace(eod[0])) {
			*c = '/';
			sx_report(SX_ERROR, "Invalid masklen in prefix %s\n",
			    text);
			goto fixups;
		};
	} else {
		masklen = -1;
	};

	if (!af) {
		if (strchr(mtext, ':'))
			af = AF_INET6;
		else
			af = AF_INET;
	};

	ret = inet_pton(af, mtext, &p->addr);

	if (ret != 1) {
		int aparts[4];
		/*
		 * contrary to documentation (man inet_ntop on FreeBSD),
		 * addresses with leading zeros are not parsed correctly. Try
		 * to workaround this issue manually.
		 */
		if (af == AF_INET && sscanf(mtext, "%i.%i.%i.%i", aparts,
		    aparts + 1, aparts + 2, aparts + 3) == 4
		    && aparts[0] >= 0 && aparts[0] < 256
		    && aparts[1] >= 0 && aparts[1] < 256
		    && aparts[2] >= 0 && aparts[2] < 256
		    && aparts[3] >= 0 && aparts[3] < 256) {
			p->addr.addr.s_addr = htonl((aparts[0] << 24) +
			    (aparts[1] << 16) + (aparts[2] << 8) + aparts[3]);
		} else {
			if (c)
				*c = '/';

			sx_report(SX_ERROR,"Unable to parse prefix '%s', af=%i"
			    " (%s), ret=%i\n", mtext, af,
			    af == AF_INET ? "inet" : "inet6", ret);
			goto fixups;
		};
	};

	if (af == AF_INET) {
		if (masklen == -1)
			p->masklen = 32;
		else {
			if(masklen < 0 || masklen > 32) {
				p->masklen = 32;
			} else {
				p->masklen = masklen;
			};
		};
	} else if (af == AF_INET6) {
		if (masklen == -1)
			p->masklen = 128;
		else {
			if (masklen < 0 || masklen > 128) {
				p->masklen = 128;
			} else {
				p->masklen = masklen;
			};
		};
	} else {
		sx_report(SX_ERROR, "Invalid address family %i\n", af);
		goto fixups;
	};

	p->family = af;
	sx_prefix_adjust_masklen(p);

	if (c)
		*c = '/';

	return 1;

fixups:
	return 0;
};

int
sx_prefix_isbitset(struct sx_prefix* p, int n)
{
	unsigned char s;

	/* bits outside the prefix considered unset */
	if (p->family == AF_INET && (n < 0 || n > 32))
		return 0;
	else if (p->family == AF_INET6 && (n < 0 || n > 128))
		return 0;
	s = p->addr.addrs[(n - 1) / 8];

	return (s & (0x80 >> ((n - 1) % 8))) ? 1 : 0;
};

void
sx_prefix_setbit(struct sx_prefix* p, int n)
{
	unsigned char* s;

	if (p->family == AF_INET && (n < 0 || n > 32))
		return;
	else if (p->family == AF_INET6 && (n < 0 || n > 128))
		return;

	s = p->addr.addrs + (n - 1) / 8;

	(*s) |= 0x80 >> ((n - 1) % 8);
};


int
sx_radix_tree_insert_specifics(struct sx_radix_tree* t, struct sx_prefix *p,
    unsigned min, unsigned max)
{
	struct sx_prefix *np;
	np = sx_prefix_alloc(p);

	if (np->masklen >= min) {
		struct sx_radix_node *nn = sx_radix_tree_insert(t, np);
		sx_prefix_destroy(np);
		np = nn->prefix;
	}

	if (np->masklen + 1 > max)
		return 1;

	np->masklen += 1;
	sx_radix_tree_insert_specifics(t, np, min, max);
	sx_prefix_setbit(np, np->masklen);
	sx_radix_tree_insert_specifics(t, np, min, max);

	return 1;
};

int
sx_prefix_range_parse(struct sx_radix_tree* tree, int af, int maxlen,
    char* text)
{
	char* d = strchr(text, '^');
	struct sx_prefix *p;
	unsigned long min, max;

	p = sx_prefix_alloc(NULL);

	if (!d || !d[1])
		return 0;

	*d = 0;

	if (!sx_prefix_parse(p, 0, text)) {
		sx_report(SX_ERROR, "Unable to parse prefix %s^%s\n", text,
		    d+1);
		return 0;
	};

	*d = '^';

	if (af && p->family != af) {
		sx_report(SX_ERROR, "Ignoring prefix %s, wrong af %i\n", text,
		    p->family);
		return 0;
	};

	if (maxlen && p->masklen > maxlen) {
		SX_DEBUG(debug_expander, "Ignoring prefix %s, masklen %i > max"
		    " masklen %u\n", text, p->masklen, maxlen);
		return 0;
	};

	if (d[1] == '-') {
		min = p->masklen + 1;
		max = maxlen;
	} else if (d[1] == '+') {
		min = p->masklen;
		max = maxlen;
	} else if (isdigit(d[1])) {
		char* dm = NULL;
		min = strtoul(d+1, &dm, 10);
		if (dm && *dm == '-' && isdigit(dm[1])) {
			max = strtoul(dm + 1, NULL, 10);
		} else if (dm && *dm) {
			sx_report(SX_ERROR, "Unable to parse prefix-range "
			    "%s\n", text);
			return 0;
		};
	} else {
		sx_report(SX_ERROR, "Invalid prefix-range %s\n", text);
		return 0;
	};

	if (min < p->masklen) {
		sx_report(SX_ERROR, "Invalid prefix-range %s: min %lu < "
		    "masklen %u\n", text, min, p->masklen);
		return 0;
	};

	if (af == AF_INET && max > 32) {
		sx_report(SX_ERROR, "Invalid prefix-range %s: max %lu > "
		    "32\n", text, max);
		return 0;
	} else if (af == AF_INET6 && max > 128) {
		sx_report(SX_ERROR, "Invalid ipv6 prefix-range %s: max %lu > "
		    "128\n", text, max);
		return 0;
	};

	if (max > maxlen)
		max = maxlen;

	SX_DEBUG(debug_expander, "parsed prefix-range %s as %lu-%lu (maxlen: "
	    "%u)\n", text, min, max, maxlen);

	sx_radix_tree_insert_specifics(tree, p, min, max);

	return 1;
};

struct sx_prefix*
sx_prefix_new(int af, char* text)
{
	struct sx_prefix* p = NULL;

	if (!text)
		return NULL;

	p = sx_prefix_alloc(NULL);

	if (!p)
		return NULL;

	if (!sx_prefix_parse(p, af, text)) {
		sx_prefix_destroy(p);
		return NULL;
	};

	return p;
};

int
sx_prefix_fprint(FILE* f, struct sx_prefix* p)
{
	char buffer[128];

	if (!p) {
		fprintf(f?f:stdout,"(null)");
		return 0;
	};

	inet_ntop(p->family, &p->addr, buffer, sizeof(buffer));
	return fprintf( f ? f : stdout, "%s/%i", buffer, p->masklen);
};

int
sx_prefix_snprintf_sep(struct sx_prefix* p, char* rbuffer, int srb, char* sep)
{
	char buffer[128];

	if (!sep)
		sep="/";

	if (!p) {
		snprintf(rbuffer, srb, "(null)");
		return 0;
	};

	inet_ntop(p->family, &p->addr, buffer, sizeof(buffer));

	return snprintf(rbuffer, srb, "%s%s%i", buffer, sep, p->masklen);
};

int
sx_prefix_snprintf(struct sx_prefix* p, char* rbuffer, int srb)
{
	return sx_prefix_snprintf_sep(p, rbuffer, srb, "/");
};

int
sx_prefix_snprintf_fmt(struct sx_prefix* p, char* buffer, int size,
    const char* name, const char* format)
{
	unsigned off = 0;
	const char* c = format;
	struct sx_prefix *q = sx_prefix_alloc(NULL);

	while (*c) {
		if(*c == '%') {
			switch (*(c + 1)) {
			case 'r':
			case 'n':
				inet_ntop(p->family, &p->addr, buffer+off, size-off);
				off = strlen(buffer);
				break;
			case 'l':
				off += snprintf(buffer + off, size - off,
				    "%i", p->masklen);
				break;
			case '%':
				buffer[off++] = '%';
				break;
			case 'N':
				off += snprintf(buffer + off, size - off,
				    "%s", name);
				break;
			case 'm':
				sx_prefix_mask(p, q);
				inet_ntop(p->family, &q->addr, buffer + off,
				    size - off);
				off = strlen(buffer);
				break;
			case 'i':
				sx_prefix_imask(p, q);
				inet_ntop(p->family, &q->addr, buffer + off,
				    size - off);
				off = strlen(buffer);
				break;
			default :
				sx_report(SX_ERROR, "Unknown format char "
				    "'%c'\n", *(c + 1));
				return 0;
			};
			c += 2;
		} else if (*c == '\\') {
			switch(*(c+1)) {
			case 'n':
				buffer[off++] = '\n';
				break;
			case 't':
				buffer[off++] = '\t';
				break;
			case '\\':
				buffer[off++] = '\\';
				break;
			default:
				buffer[off++] = *(c + 1);
				break;
			};
			c += 2;
		} else {
			buffer[off++] = *c;
			c++;
		};
	};

	return strlen(buffer);
};

int
sx_prefix_jsnprintf(struct sx_prefix* p, char* rbuffer, int srb)
{
	char buffer[128];

	if (!p) {
		snprintf(rbuffer, srb, "(null)");
		return 0;
	};
	inet_ntop(p->family, &p->addr, buffer, sizeof(buffer));

	return snprintf(rbuffer, srb, "%s\\/%i", buffer, p->masklen);
};

struct sx_radix_tree*
sx_radix_tree_new(int af)
{
	struct sx_radix_tree* rt = malloc(sizeof(struct sx_radix_tree));

	if (!rt)
		return NULL;

	memset(rt, 0, sizeof(struct sx_radix_tree));
	rt->family = af;

	return rt;
};

int
sx_radix_tree_empty(struct sx_radix_tree* t)
{
	return t->head == NULL;
};

struct sx_radix_node*
sx_radix_node_new(struct sx_prefix* prefix)
{
	struct sx_radix_node* rn = malloc(sizeof(struct sx_radix_node));

	if (!rn)
		return NULL;

	memset(rn, 0, sizeof(struct sx_radix_node));

	if (prefix)
		rn->prefix = sx_prefix_alloc(prefix);

	return rn;
};

int
sx_prefix_eqbits(struct sx_prefix* a, struct sx_prefix* b)
{
	int i;
	int nbytes = (a->family == AF_INET ? 4 : 16);

	for (i = 0; i < nbytes; i++) {

		if (a->addr.addrs[i] == b->addr.addrs[i])
			continue;
		else {
			int j;
			for (j = 0; j < 8 && i * 8 + j <= a->masklen
			    && i * 8 + j<= b->masklen; j++) {
				if ((a->addr.addrs[i] & (0x80 >> j))
				    != (b->addr.addrs[i] & (0x80 >> j)))
					return i * 8 + j;
			};
		};
	};

	if (a->masklen < b->masklen)
		return a->masklen;

	return b->masklen;
};

struct sx_prefix*
sx_prefix_overlay(struct sx_prefix* p, int n)
{
	struct sx_prefix* sp = sx_prefix_alloc(p);
	sp->masklen = n;
	sx_prefix_adjust_masklen(sp);

	return sp;
};

void
sx_radix_tree_unlink(struct sx_radix_tree* tree, struct sx_radix_node* node)
{
next:
	if (node->r && node->l)
		node->isGlue = 1;
	else if (node->r) {
		if (node->parent) {
			if (node->parent->r == node) {
				node->parent->r = node->r;
				node->r->parent = node->parent;
			} else if (node->parent->l == node) {
				node->parent->l = node->r;
				node->r->parent = node->parent;
			} else {
				sx_report(SX_ERROR,"Unlinking node which is "
				    "not descendant of its parent\n");
			};
		} else if (tree->head == node) {
			/* only one case, really */
			tree->head = node->r;
			node->r->parent = NULL;
		} else {
			sx_report(SX_ERROR,"Unlinking node with no parent and"
			    " not root\n");
		};
		sx_radix_node_destroy(node);
		return;
	} else if (node->l) {
		if (node->parent) {
			if (node->parent->r == node) {
				node->parent->r = node->l;
				node->l->parent = node->parent;
			} else if(node->parent->l==node) {
				node->parent->l=node->l;
				node->l->parent=node->parent;
			} else {
				sx_report(SX_ERROR,"Unlinking node which is not descendant "
					"of its parent\n");
			};
		} else if(tree->head==node) {
			tree->head=node->l;
			node->l->parent=NULL;
		} else {
			sx_report(SX_ERROR,"Unlinking node with no parent and not root\n");
		};
		sx_radix_node_destroy(node);
		return;
	} else {
		/* the only case - node does not have descendants */
		if (node->parent) {
			if(node->parent->l == node)
				node->parent->l = NULL;
			else if (node->parent->r == node)
				node->parent->r=NULL;
			else {
				sx_report(SX_ERROR,"Unlinking node which is "
				    "not descendant of its parent\n");
			};

			if (node->parent->isGlue) {
				node = node->parent;
				goto next;
			};
		} else if (tree->head==node) {
			tree->head = NULL;
		} else {
			sx_report(SX_ERROR, "Unlinking node with no parent and"
			    " not root\n");
		};
		sx_radix_node_destroy(node);
		return;
	};
};
	
			
struct sx_radix_node*
sx_radix_tree_lookup(struct sx_radix_tree* tree, struct sx_prefix* prefix)
{
	int eb;
	struct sx_radix_node* candidate = NULL, *chead;

	if (!tree || !prefix)
		return NULL;

	if (tree->family!=prefix->family)
		return NULL;

	if (!tree->head)
		return NULL;

	chead = tree->head;

next:
	eb = sx_prefix_eqbits(chead->prefix, prefix);
	if (eb == chead->prefix->masklen && eb == prefix->masklen) {
		/* they are equal */
		if (chead->isGlue)
			return candidate;
		return chead;
	} else if (eb < chead->prefix->masklen) {
		return candidate;
	} else if (eb < prefix->masklen) {
		/* it equals chead->masklen */
		if (sx_prefix_isbitset(prefix, eb + 1)) {
			if (chead->r) {
				if (!chead->isGlue) {
					candidate = chead;
				};
				chead = chead->r;
				goto next;
			} else {
				if (chead->isGlue)
					return candidate;
				return chead;
			};
		} else {
			if (chead->l) {
				if (!chead->isGlue) {
					candidate = chead;
				};
				chead = chead->l;
				goto next;
			} else {
				if (chead->isGlue)
					return candidate;
				return chead;
			};
		};
	} else {
		char pbuffer[128], cbuffer[128];
		sx_prefix_snprintf(prefix, pbuffer, sizeof(pbuffer));
		sx_prefix_snprintf(chead->prefix, cbuffer, sizeof(cbuffer));
		printf("Unreachible point... eb=%i, prefix=%s, chead=%s\n",
		    eb, pbuffer, cbuffer);
		abort();
	};
};


struct sx_radix_node*
sx_radix_tree_insert(struct sx_radix_tree* tree, struct sx_prefix* prefix)
{
	int eb;
	struct sx_radix_node** candidate=NULL, *chead;

	if (!tree || !prefix)
		return NULL;

	if (tree->family!=prefix->family)
		return NULL;

	if (!tree->head) {
		tree->head=sx_radix_node_new(prefix);
		return tree->head;
	};

	candidate = &tree->head;
	chead = tree->head;

next:
	eb = sx_prefix_eqbits(prefix, chead->prefix);
	if (eb < prefix->masklen && eb < chead->prefix->masklen) {
		struct sx_prefix *neoRoot = sx_prefix_alloc(prefix);
		
		struct sx_radix_node* rn, *ret=sx_radix_node_new(prefix);
		neoRoot->masklen = eb;
		sx_prefix_adjust_masklen(neoRoot);
		rn=sx_radix_node_new(neoRoot);
                sx_prefix_destroy(neoRoot);
                neoRoot = rn->prefix;
		if (!rn) {
			sx_report(SX_ERROR,"Unable to create node: %s\n",
			    strerror(errno));
			return NULL;
		};

		if (sx_prefix_isbitset(prefix, eb + 1)) {
			rn->l = chead;
			rn->r = ret;
		} else {
			rn->l = ret;
			rn->r = chead;
		};

		rn->parent = chead->parent;
		chead->parent = rn;
		ret->parent = rn;
		rn->isGlue = 1;
		*candidate = rn;
		return ret;
	} else if (eb == prefix->masklen && eb < chead->prefix->masklen) {
		struct sx_radix_node* ret = sx_radix_node_new(prefix);
		if (sx_prefix_isbitset(chead->prefix, eb + 1)) {
			ret->r = chead;
		} else {
			ret->l = chead;
		};
		ret->parent = chead->parent;
		chead->parent = ret;
		*candidate = ret;
		return ret;
	} else if (eb == chead->prefix->masklen && eb < prefix->masklen) {
		if (sx_prefix_isbitset(prefix, eb + 1)) {
			if (chead->r) {
				candidate = &chead->r;
				chead = chead->r;
				goto next;
			} else {
				chead->r = sx_radix_node_new(prefix);
				chead->r->parent = chead;
				return chead->r;
			};
		} else {
			if (chead->l) {
				candidate = &chead->l;
				chead = chead->l;
				goto next;
			} else {
				chead->l = sx_radix_node_new(prefix);
				chead->l->parent = chead;
				return chead->l;
			};
		};
	} else if (eb == chead->prefix->masklen && eb == prefix->masklen) {
		/* equal routes... */
		if (chead->isGlue) {
			chead->isGlue = 0;
		};
		return chead;
	} else {
		char pbuffer[128], cbuffer[128];
		sx_prefix_snprintf(prefix, pbuffer, sizeof(pbuffer));
		sx_prefix_snprintf(chead->prefix, cbuffer, sizeof(cbuffer));
		printf("Unreachible point... eb=%i, prefix=%s, chead=%s\n", eb,
		    pbuffer, cbuffer);
		abort();
	};
}

void
sx_radix_node_fprintf(struct sx_radix_node* node, void* udata)
{
	FILE* out = (udata?udata:stdout);
	char buffer[128];
	if (!node) {
		fprintf(out, "(null)\n");
	} else {
		sx_prefix_snprintf(node->prefix, buffer, sizeof(buffer));
		fprintf(out, "%s %s\n", buffer, node->isGlue ? "(glue)" : "");
	};
};

int
sx_radix_node_foreach(struct sx_radix_node* node,
    void (*func)(struct sx_radix_node*, void*), void* udata)
{
	func(node,udata);

	if (node->l)
		sx_radix_node_foreach(node->l, func, udata);

	if (node->r)
		sx_radix_node_foreach(node->r, func, udata);

	return 0;
};

int
sx_radix_tree_foreach(struct sx_radix_tree* tree,
	void (*func)(struct sx_radix_node*, void*), void* udata)
{
	if(!func || !tree || !tree->head) return 0;
	sx_radix_node_foreach(tree->head,func,udata);
	return 0;
};

int
sx_radix_node_aggregate(struct sx_radix_node* node)
{
	if(node->l)
		sx_radix_node_aggregate(node->l);
	if(node->r)
		sx_radix_node_aggregate(node->r);

	if(debug_aggregation) {
		printf("Aggregating on node: ");
		sx_prefix_fprint(stdout,node->prefix);
		printf(" %s%s%u,%u\n", node->isGlue?"Glue ":"",
			node->isAggregate?"Aggregate ":"",node->aggregateLow,
			node->aggregateHi);
		if (node->r) {
			printf("R-Tree: ");
			sx_prefix_fprint(stdout, node->r->prefix);
			printf(" %s%s%u,%u\n",
			    (node->r->isGlue) ? "Glue " : "",
			    (node->r->isAggregate) ? " Aggregate ": "",
			    node->r->aggregateLow, node->r->aggregateHi);
			if (node->r->son) {
				printf("R-Son: ");
			sx_prefix_fprint(stdout, node->r->son->prefix);
			printf(" %s%s%u,%u\n",
			    node->r->son->isGlue ? "Glue " : "",
			    node->r->son->isAggregate ? "Aggregate " : "",
			    node->r->son->aggregateLow,
			    node->r->son->aggregateHi);
			};
		};
		if (node->l) {
			printf("L-Tree: ");
			sx_prefix_fprint(stdout, node->l->prefix);
			printf(" %s%s%u,%u\n", node->l->isGlue ? "Glue ": "",
			    node->l->isAggregate ? "Aggregate ": "",
			    node->l->aggregateLow, node->l->aggregateHi);
			if (node->l->son) {
				printf("L-Son: ");
				sx_prefix_fprint(stdout, node->l->son->prefix);
				printf(" %s%s%u,%u\n",
				    node->l->son->isGlue ? "Glue " : "",
				    node->l->son->isAggregate ? "Aggregate " : "",
				    node->l->son->aggregateLow,
				    node->l->son->aggregateHi);
			};
		};
	};

	if (node->r && node->l) {
		if (!node->r->isAggregate && !node->l->isAggregate
		    && !node->r->isGlue && !node->l->isGlue
		    && node->r->prefix->masklen == node->l->prefix->masklen) {
			if (node->r->prefix->masklen == node->prefix->masklen+1) {
				node->isAggregate = 1;
				node->r->isGlue = 1;
				node->l->isGlue = 1;
				node->aggregateHi = node->r->prefix->masklen;
				if (node->isGlue) {
					node->isGlue = 0;
					node->aggregateLow = node->r->prefix->masklen;
				} else {
					node->aggregateLow = node->prefix->masklen;
				};
			};
			if (node->r->son && node->l->son
			    && node->r->son->isAggregate
			    && node->l->son->isAggregate
			    && node->r->son->aggregateHi == node->l->son->aggregateHi
			    && node->r->son->aggregateLow == node->l->son->aggregateLow
			    && node->r->prefix->masklen == node->prefix->masklen + 1
			    && node->l->prefix->masklen == node->prefix->masklen + 1) {
				node->son = sx_radix_node_new(node->prefix);
				node->son->isGlue = 0;
				node->son->isAggregate = 1;
				node->son->aggregateHi = node->r->son->aggregateHi;
				node->son->aggregateLow = node->r->son->aggregateLow;
				node->r->son->isGlue = 1;
				node->l->son->isGlue = 1;
			};
		} else if (node->r->isAggregate && node->l->isAggregate
		    && node->r->aggregateHi == node->l->aggregateHi
		    && node->r->aggregateLow==node->l->aggregateLow) {
			if (node->r->prefix->masklen == node->prefix->masklen + 1
			    && node->l->prefix->masklen == node->prefix->masklen + 1) {
				if (node->isGlue) {
					node->r->isGlue = 1;
					node->l->isGlue = 1;
					node->isAggregate = 1;
					node->isGlue = 0;
					node->aggregateHi = node->r->aggregateHi;
					node->aggregateLow = node->r->aggregateLow;
				} else if (node->r->prefix->masklen == node->r->aggregateLow) {
					node->r->isGlue = 1;
					node->l->isGlue = 1;
					node->isAggregate = 1;
					node->aggregateHi = node->r->aggregateHi;
					node->aggregateLow = node->prefix->masklen;
				} else {
					node->son = sx_radix_node_new(node->prefix);
					node->son->isGlue = 0;
					node->son->isAggregate = 1;
					node->son->aggregateHi = node->r->aggregateHi;
					node->son->aggregateLow = node->r->aggregateLow;
					node->r->isGlue = 1;
					node->l->isGlue = 1;
					if (node->r->son && node->l->son
					    && node->r->son->aggregateHi == node->l->son->aggregateHi
					    && node->r->son->aggregateLow == node->l->son->aggregateLow) {
						node->son->son = sx_radix_node_new(node->prefix);
						node->son->son->isGlue = 0;
						node->son->son->isAggregate = 1;
						node->son->son->aggregateHi = node->r->son->aggregateHi;
						node->son->son->aggregateLow = node->r->son->aggregateLow;
						node->r->son->isGlue = 1;
						node->l->son->isGlue = 1;
					};
				};
			};
		} else if (node->l->son && node->r->isAggregate
		    && node->l->son->isAggregate
		    && node->r->aggregateHi == node->l->son->aggregateHi
		    && node->r->aggregateLow == node->l->son->aggregateLow) {
			if (node->r->prefix->masklen == node->prefix->masklen + 1
			    && node->l->prefix->masklen == node->prefix->masklen + 1) {
				if (node->isGlue) {
					node->r->isGlue = 1;
					node->l->son->isGlue = 1;
					node->isAggregate = 1;
					node->isGlue = 0;
					node->aggregateHi = node->r->aggregateHi;
					node->aggregateLow = node->r->aggregateLow;
				} else {
					node->son = sx_radix_node_new(node->prefix);
					node->son->isGlue = 0;
					node->son->isAggregate = 1;
					node->son->aggregateHi = node->r->aggregateHi;
					node->son->aggregateLow = node->r->aggregateLow;
					node->r->isGlue = 1;
					node->l->son->isGlue = 1;
				};
			};
		} else if (node->r->son && node->l->isAggregate
		    && node->r->son->isAggregate
		    && node->l->aggregateHi == node->r->son->aggregateHi
		    && node->l->aggregateLow == node->r->son->aggregateLow) {
			if (node->l->prefix->masklen == node->prefix->masklen + 1
			    && node->r->prefix->masklen == node->prefix->masklen+1) {
				if (node->isGlue) {
					node->l->isGlue = 1;
					node->r->son->isGlue = 1;
					node->isAggregate = 1;
					node->isGlue = 0;
					node->aggregateHi = node->l->aggregateHi;
					node->aggregateLow = node->l->aggregateLow;
				} else {
					node->son = sx_radix_node_new(node->prefix);
					node->son->isGlue = 0;
					node->son->isAggregate = 1;
					node->son->aggregateHi = node->l->aggregateHi;
					node->son->aggregateLow = node->l->aggregateLow;
					node->l->isGlue = 1;
					node->r->son->isGlue = 1;
				};
			};
		};
	};

	return 0;
};

int
sx_radix_tree_aggregate(struct sx_radix_tree* tree)
{
	if (tree && tree->head)
		return sx_radix_node_aggregate(tree->head);

	return 0;
};

static void
setGlueUpTo(struct sx_radix_node* node, void* udata)
{
	unsigned refine = *(unsigned*)udata;

	if (node && node->prefix->masklen <= refine)
		node->isGlue = 1;
};

int
sx_radix_node_refine(struct sx_radix_node* node, unsigned refine)
{
	if (!node->isGlue && node->prefix->masklen<refine) {
		node->isAggregate = 1;
		node->aggregateLow = node->prefix->masklen;
		node->aggregateHi = refine;
		if (node->l) {
			sx_radix_node_foreach(node->l, setGlueUpTo, &refine);
			sx_radix_node_refine(node->l, refine);
		};
		if (node->r) {
			sx_radix_node_foreach(node->r, setGlueUpTo, &refine);
			sx_radix_node_refine(node->r, refine);
		};
	} else if (!node->isGlue && node->prefix->masklen == refine) {
		/* not setting aggregate in this case */
		if (node->l)
			sx_radix_node_refine(node->l, refine);
		if (node->r)
			sx_radix_node_refine(node->r, refine);
	} else if (node->isGlue) {
		if (node->r)
			sx_radix_node_refine(node->r, refine);
		if (node->l)
			sx_radix_node_refine(node->l, refine);
	} else {
		/* node->prefix.masklen > refine */
		/*
		 * do nothing, should pass specifics 'as is'. Also, do not
		 * process any embedded routes, their masklen is bigger, too...
		node->isGlue = 1;
		if (node->l)
			sx_radix_node_foreach(node->l, setGlue, NULL);

		if (node->r)
			sx_radix_node_foreach(node->r, setGlue, NULL);
		*/
	};
	return 0;
};
	
int
sx_radix_tree_refine(struct sx_radix_tree* tree, unsigned refine)
{
	if (tree && tree->head)
		return sx_radix_node_refine(tree->head, refine);

	return 0;
};

static void
setGlueFrom(struct sx_radix_node* node, void* udata)
{
	unsigned refine = *(unsigned*)udata;

	if (node && node->prefix->masklen <= refine)
		node->isGlue=1;
};

static int
sx_radix_node_refineLow(struct sx_radix_node* node, unsigned refineLow)
{
	if (!node->isGlue && node->prefix->masklen<=refineLow) {

		if (!node->isAggregate) {
			node->isAggregate = 1;
			node->aggregateLow = refineLow;
			if (node->prefix->family == AF_INET)
				node->aggregateHi = 32;
			else
				node->aggregateHi = 128;
		} else
			node->aggregateLow=refineLow;

		if (node->l) {
			sx_radix_node_foreach(node->l, setGlueFrom, &refineLow);
			sx_radix_node_refineLow(node->l, refineLow);
		};

		if (node->r) {
			sx_radix_node_foreach(node->r, setGlueFrom, &refineLow);
			sx_radix_node_refineLow(node->r, refineLow);
		};

	} else if (!node->isGlue && node->prefix->masklen == refineLow) {
		/* not setting aggregate in this case */
		if (node->l)
			sx_radix_node_refineLow(node->l, refineLow);
		if (node->r)
			sx_radix_node_refineLow(node->r, refineLow);
	} else if (node->isGlue) {
		if (node->r)
			sx_radix_node_refineLow(node->r, refineLow);
		if (node->l)
			sx_radix_node_refineLow(node->l, refineLow);
	} else {
		/* node->prefix.masklen > refine */
		/* do nothing, should pass specifics 'as is'. Also, do not
		process any embedded routes, their masklen is bigger, too...
		node->isGlue = 1;
		if (node->l)
			sx_radix_node_foreach(node->l, setGlue, NULL);
		if (node->r)
			sx_radix_node_foreach(node->r, setGlue, NULL);
		*/
	};

	return 0;
};

int
sx_radix_tree_refineLow(struct sx_radix_tree* tree, unsigned refineLow)
{
	if (tree && tree->head)
		return sx_radix_node_refineLow(tree->head, refineLow);

	return 0;
};

#if SX_PTREE_TEST
int
main() {
	struct sx_prefix* p;
	int n;
	struct sx_radix_tree* tree;
	struct sx_radix_node* node;

	p = sx_prefix_new(0, "10.11.12.13/24");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "10.11.12.13/33");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "10.11.12.13/-133");
	sx_prefix_fprint(stdout, p);
	printf("\n");

	p = sx_prefix_new(AF_INET, "10.11.12.14/24");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(AF_INET, "10.11.12.14/33");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(AF_INET, "10.11.12.14/-133");
	sx_prefix_fprint(stdout, p);
	printf("\n");

	p = sx_prefix_new(AF_INET6, "10.11.12.15/24");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(AF_INET6, "10.11.12.15/33");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(AF_INET6, "10.11.12.15/-133");
	sx_prefix_fprint(stdout, p);
	printf("\n");

	p = sx_prefix_new(0, "2001:1b00::/24");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "2001:1b00::/33");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "2001:1b00::/-133");
	sx_prefix_fprint(stdout, p);
	printf("\n");

	p = sx_prefix_new(AF_INET6, "2001:1b01::/24");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(AF_INET6, "2001:1b01::/33");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(AF_INET6, "2001:1b01::/-133");
	sx_prefix_fprint(stdout, p);
	printf("\n");

#define SX_TEST_EBITS(a,b,susp) n = sx_prefix_eqbits(sx_prefix_new(0,a)),\
		sx_prefix_new(0,b))); \
		if (n != susp) \
			printf("FAILED: %s eqbits %s=%i, not %i\n", a, b, n,
			     susp);\
		else
			printf("OK, %s eqbits %s = %i, as suspected\n", a, b,
			    n);
	SX_TEST_EBITS("192.168.0.0/24", "192.168.1.0/24", 23);
	SX_TEST_EBITS("192.168.0.0/32", "192.168.0.1/32", 31);
#if SX_LIBPTREE_IPV6
	SX_TEST_EBITS("2001:1b00::/32", "2001:1b01::/32", 31);
#endif

	p = sx_prefix_new(0, "10.11.12.255/32");
	sx_prefix_fprint(stdout, p);
	printf("\n31'th bit is %i\n",sx_prefix_isbitset(p, 31));
	printf("32'th bit is %i\n",sx_prefix_isbitset(p, 32));
	printf("33'th bit is %i\n",sx_prefix_isbitset(p, 33));
	p = sx_prefix_new(0, "10.11.12.255/31");
	sx_prefix_fprint(stdout, p);
	printf("\n31'th bit is %i\n", sx_prefix_isbitset(p, 31));
	printf("32'th bit is %i\n", sx_prefix_isbitset(p, 32));
	printf("33'th bit is %i\n", sx_prefix_isbitset(p, 33));
	p = sx_prefix_new(0, "10.11.12.255/30");
	sx_prefix_fprint(stdout, p);
	printf("\n31'th bit is %i\n", sx_prefix_isbitset(p, 31));
	p = sx_prefix_new(0, "10.11.12.255/29");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "10.11.12.255/28");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "10.11.12.255/27");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "10.11.12.255/26");
	sx_prefix_fprint(stdout, p);
	printf("\n");
	p = sx_prefix_new(0, "10.11.12.255/25");
	sx_prefix_fprint(stdout, p);
	printf("\n25'th bit is %i\n", sx_prefix_isbitset(p, 25));
	p = sx_prefix_new(0, "10.11.12.255/24");
	sx_prefix_fprint(stdout, p);
	printf("\n25'th bit is %i\n", sx_prefix_isbitset(p, 25));

	tree = sx_radix_tree_new(AF_INET);
	sx_radix_tree_insert(tree, sx_prefix_new(0, "81.9.100.10/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.83/32"));

	sx_radix_tree_foreach(tree, sx_radix_node_fprintf, NULL);

	tree = sx_radix_tree_new(AF_INET);
	sx_radix_tree_insert(tree, sx_prefix_new(0, "81.9.100.10/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.83/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.84/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.85/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.86/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.87/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.90/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.90/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "127.0.0.1/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "127.0.0.1/24"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "127.0.0.0/24"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "128.0.0.0/1"));

	sx_radix_tree_foreach(tree, sx_radix_node_fprintf, NULL);

	printf("lookup 1.1.1.1: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "1.1.1.1"));
	sx_radix_node_fprintf(node, NULL);

	printf("lookup 217.170.80.90: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "217.170.80.90"));
	sx_radix_node_fprintf(node, NULL);

	sx_radix_tree_unlink(tree, node);
	printf("lookup 217.170.80.90 after delete: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "217.170.80.90"));
	sx_radix_node_fprintf(node, NULL);

	sx_radix_tree_insert(tree, sx_prefix_new(0, "217.170.80.90/32"));
	printf("lookup 217.170.80.90 after reinsert: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "217.170.80.90"));
	sx_radix_node_fprintf(node, NULL);

	printf("lookup 217.170.80.81: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "217.170.80.81"));
	sx_radix_node_fprintf(node, NULL);

	printf("lookup 127.0.0.1/24: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "127.0.0.1/24"));
	sx_radix_node_fprintf(node, NULL);

	printf("lookup 127.0.0.1/26: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "127.0.0.1/26"));
	sx_radix_node_fprintf(node, NULL);

	printf("lookup 127.0.0.1/23: ");
	node = sx_radix_tree_lookup(tree, sx_prefix_new(0, "127.0.0.1/23"));
	sx_radix_node_fprintf(node, NULL);

	tree = sx_radix_tree_new(AF_INET6);
	sx_radix_tree_insert(tree, sx_prefix_new(0, "2100:1b00::/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "2100:1b01::/32"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "2100:1b00::/33"));
	sx_radix_tree_insert(tree, sx_prefix_new(0, "2100:1b00::1/128"));
	sx_radix_tree_foreach(tree, sx_radix_node_fprintf, NULL);

	return 0;
};

#endif
