/*
 * Copyright (c) 2019-2021 Job Snijders <job@sobornost.net>
 * Copyright (c) 2018 Peter Schoenmaker <pds@ntt.net>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "extern.h"
#include "sx_report.h"

int debug_expander = 0;
int pipelining = 1;
int expand_special_asn = 0;

static inline int
tentry_cmp(struct sx_tentry *a, struct sx_tentry *b)
{
	return strcasecmp(a->text, b->text);
}

RB_GENERATE_STATIC(tentree, sx_tentry, entry, tentry_cmp);

int
asn_cmp(struct asn_entry *a, struct asn_entry *b)
{
	return (a->asn < b->asn ? -1 : a->asn > b->asn);
}

RB_GENERATE(asn_tree, asn_entry, entry, asn_cmp);

int
bgpq_expander_init(struct bgpq_expander *b, int af)
{
	if (!af)
		af = AF_INET;

	if (!b)
		return 0;

	memset(b, 0, sizeof(struct bgpq_expander));

	b->tree = sx_radix_tree_new(af);

	if (!b->tree)
		goto fixups;

	b->family = af;
	b->sources = "";
	b->usesource = 0;
	b->name = "NN";
	b->aswidth = 8;
	b->identify = 1;
	b->server = "rr.ntt.net";
	b->port = "43";

	RB_INIT(&b->asnlist);

	STAILQ_INIT(&b->wq);
	STAILQ_INIT(&b->rq);
	STAILQ_INIT(&b->rsets);
	STAILQ_INIT(&b->macroses);

	return 1;

fixups:
	if (b->tree)
		sx_radix_tree_freeall(b->tree);

	b->tree = NULL;
	free(b);

	return 0;
}

int
bgpq_expander_add_asset(struct bgpq_expander *b, char *as)
{
	struct slentry	*le;

	if (!b || !as)
		return 0;

	le = sx_slentry_new(as);

	STAILQ_INSERT_TAIL(&b->macroses, le, entry);

	return 1;
}

int
bgpq_expander_add_rset(struct bgpq_expander *b, char *rs)
{
	struct slentry	*le;

	if (!b || !rs)
		return 0;

	le = sx_slentry_new(rs);

	if (!le)
		return 0;

	STAILQ_INSERT_TAIL(&b->rsets, le, entry);

	return 1;
}

static int
bgpq_expander_add_already(struct bgpq_expander *b, char *rs)
{
	struct sx_tentry	*le, lkey;

	lkey.text = rs;

	if (RB_FIND(tentree, &b->already, &lkey))
		return 0;

	le = sx_tentry_new(rs);

	RB_INSERT(tentree, &b->already, le);

	return 1;
}

int
bgpq_expander_add_stop(struct bgpq_expander *b, char *rs)
{
	struct sx_tentry	*le, lkey;

	lkey.text = rs;

	if (RB_FIND(tentree, &b->stoplist, &lkey))
		return 0;

	le = sx_tentry_new(rs);

	RB_INSERT(tentree, &b->stoplist, le);

	return 1;
}

int
bgpq_expander_add_as(struct bgpq_expander *b, char *as)
{
	char			*eoa;
	uint32_t	 	 asno = 0;
	struct asn_entry	*asne;

	if (!b || !as)
		return 0;

	asno = strtoul(as + 2, &eoa, 10);
	if (eoa && *eoa != 0) {
		sx_report(SX_ERROR,"Invalid symbol in AS number: '%c' in %s\n",
		    *eoa, as);
		return 0;
	}

	if (!expand_special_asn &&
	    ((asno  >= 4200000000ul) || (asno >= 64496 && asno <= 65551))) {
		sx_report(SX_ERROR,"Invalid AS number: %u\n", asno);
		return 0;
	}

	if ((asne = malloc(sizeof(struct asn_entry))) == NULL)
		sx_report(SX_FATAL, "malloc failed for asn\n");

	asne->asn = asno;
	RB_INSERT(asn_tree, &b->asnlist, asne);

	return 1;
}

int
bgpq_expander_add_prefix(struct bgpq_expander *b, char *prefix)
{
	struct sx_prefix *p = sx_prefix_alloc(NULL);

	if (!sx_prefix_parse(p, 0, prefix)) {
		sx_report(SX_ERROR, "Unable to parse prefix %s\n", prefix);
		return 0;
	} else if (p->family != b->family) {
		SX_DEBUG(debug_expander, "Ignoring prefix %s with wrong "
		    "address family\n", prefix);
		return 0;
	}
	if (b->maxlen && p->masklen>b->maxlen) {
		SX_DEBUG(debug_expander, "Ignoring prefix %s: masklen %i > max"
		    " masklen %u\n", prefix, p->masklen, b->maxlen);
		return 0;
	}
	sx_radix_tree_insert(b->tree, p);

        if (p)
		sx_prefix_free(p);

	return 1;
}

int
bgpq_expander_add_prefix_range(struct bgpq_expander *b, char *prefix)
{
	return sx_prefix_range_parse(b->tree, b->family, b->maxlen, prefix);
}

char*
bgpq_get_asset(char *object){
	char *asset, *d;

	d = strstr(object, "::");
	if (d){
		d += 2;
	} else {
		d = object;
	}

	if ((asset = calloc(1, 256)) == NULL)
		sx_report(SX_FATAL, "calloc failed for asset\n");
	memcpy(asset, d, strlen(object) - (d - object));
	return asset;
}

char*
bgpq_get_rset(char *object){
	char *d = strstr(object, "::");
	if (d){
		d += 2;
	} else {
		d = object;
	}

	char *rset = (char*)calloc(1, 256);
	memcpy(rset, d, strlen(object) - (d - object));
	return rset;
}

char*
bgpq_get_source(char *object){
	char *d = strstr(object, "::");
	if (d){
		char *source = (char*)calloc(1, 256);
		unsigned int slen = d - object;
		memcpy(source, object, slen);
		return source;
	}
	return NULL;
}

static int
bgpq_expanded_macro(char *as, struct bgpq_expander *ex,
    struct request *req)
{
	bgpq_expander_add_as(ex, as);

	return 1;
}

struct request *bgpq_pipeline(struct bgpq_expander *b,
    int (*callback)(char *, struct bgpq_expander *b, struct request *req),
    void *udata, char *fmt, ...);

int bgpq_expand_irrd(struct bgpq_expander *b,
    int (*callback)(char*, struct bgpq_expander *b, struct request *req),
    void *udata, char *fmt, ...);

static int
bgpq_expanded_macro_limit(char *as, struct bgpq_expander *b,
    struct request *req)
{
	if (!strncasecmp(as, "AS-", 3) || strchr(as, '-') || strchr(as, ':')) {
		struct sx_tentry tkey = { .text = as };
		char *source;

		if (RB_FIND(tentree, &b->already, &tkey)) {
			SX_DEBUG(debug_expander > 2, "%s is already expanding, "
			    "ignore\n", as);
			return 0;
		}

		if (RB_FIND(tentree, &b->stoplist, &tkey)) {
			SX_DEBUG(debug_expander > 2, "%s is in the stoplist, "
			    "ignore\n", as);
			return 0;
		}

		if (!b->maxdepth ||
		    (b->cdepth + 1 < b->maxdepth &&
		    req->depth + 1 < b->maxdepth)) {
			bgpq_expander_add_already(b, as);
			if (pipelining) {
				if (b->usesource) {
					source = bgpq_get_source(as);
					if (source){
						bgpq_pipeline(b, NULL, NULL, "!s%s\n", source);
						free(source);
					} else {
						bgpq_pipeline(
							b, NULL, NULL, "!s%s\n", b->defaultsources
						);
					}
				}
				struct request *req1 = bgpq_pipeline(b,
				    bgpq_expanded_macro_limit, NULL, "!i%s\n",
				        bgpq_get_asset(as));
				req1->depth = req->depth + 1;
			} else {
				if (b->usesource) {
					source = bgpq_get_source(as);
					if (source) {
						bgpq_expand_irrd(b, NULL, NULL, "!s%s\n", source);
						free(source);
					} else {
						bgpq_expand_irrd(
							b, NULL, NULL, "!s%s\n", b->defaultsources
						);
					}
				}
				b->cdepth++;
				bgpq_expand_irrd(b, bgpq_expanded_macro_limit,
				    NULL, "!i%s\n", bgpq_get_asset(as));
				b->cdepth--;
			}
		} else {
			SX_DEBUG(debug_expander > 2, "ignoring %s at depth %i\n",
			    as,
			    b->cdepth ? (b->cdepth + 1) : (req->depth + 1));
		}
	} else if (!strncasecmp(as, "AS", 2)) {
		struct sx_tentry tkey = { .text = as };

		if (RB_FIND(tentree, &b->stoplist, &tkey)) {
			SX_DEBUG(debug_expander > 2,
			    "%s is in the stoplist, ignore\n", as);
			return 0;
		}

		if (bgpq_expander_add_as(b, as)) {
			SX_DEBUG(debug_expander > 2, ".. added asn %s\n", as);
		} else {
			SX_DEBUG(debug_expander, ".. some error adding as %s "
			    "(in response to %s)\n", as, req->request);
		}

	} else if (!strcasecmp(as, "ANY"))
		return 0;
	else
		sx_report(SX_ERROR, "unexpected object '%s' in "
		    "expanded_macro_limit (in response to %s)\n", as,
		    req->request);

	return 1;
}

static int
bgpq_expanded_prefix(char *as, struct bgpq_expander *ex,
    struct request *req __attribute__((unused)))
{
	char *d = strchr(as, '^');

	if (!d)
		bgpq_expander_add_prefix(ex, as);
	else
		bgpq_expander_add_prefix_range(ex, as);

	return 1;
}

static int
bgpq_expanded_v6prefix(char *prefix, struct bgpq_expander *ex,
    struct request *req)
{
	char *d = strchr(prefix, '^');

	if (!d)
		bgpq_expander_add_prefix(ex, prefix);
	else
		bgpq_expander_add_prefix_range(ex, prefix);

	return 1;
}

static char*
bgpq_get_irrd_sources(int fd) {
	int ret;
	char *query = "!s-lc\n";
	int qlen = strlen(query);
	const unsigned int rsize = 256;
	char *response = (char*)calloc(1, rsize);
	char *sources = (char*)calloc(1, rsize);

	SX_DEBUG(debug_expander, "Requesting source list %s", query);
	if ((ret = write(fd, query, strlen(query))) != qlen) {
		sx_report(SX_ERROR, "Partial write of query to "
			"IRRd: %i bytes, %s\n", ret, strerror(errno));
		close(fd);
		free(sources);
		free(response);
		exit(1);
	}

	if (0 < read(fd, response, rsize)) {
		SX_DEBUG(debug_expander, "Got answer %s", response);
		if (*(response + strlen(response) - 2) != 'C') {
			sx_report(SX_ERROR, "Invalid response "
				"'%s': %s\n", response, query);
			close(fd);
			free(sources);
			free(response);
			exit(1);
		}
	} else {
		sx_report(SX_ERROR, "failed to read sources\n");
		close(fd);
		free(sources);
		free(response);
		exit(1);
	}

	char *start = strchr(response, '\n');
	if (start){
		start += 1;
		char *end = strchr(start, '\n');
		if (!end) {
			sx_report(SX_ERROR, "No 2nd newline in response '%s': %s\n",
				response, query);
			close(fd);
			free(sources);
			free(response);
			exit(1);
		}
		unsigned int slen = end - start;
		if (slen > rsize) {
			memcpy(sources, start, rsize-1);
		} else {
			memcpy(sources, start, slen);
		}
	} else {
		sx_report(SX_ERROR, "No 1st newline in response '%s': %s\n",
			response, query);
		close(fd);
		free(sources);
		free(response);
		exit(1);
	}
	free(response);
	return sources;
}

int bgpq_pipeline_dequeue(int fd, struct bgpq_expander *b);

static struct request *
request_alloc(char *request, int (*callback)(char *, struct bgpq_expander *,
    struct request *), void *udata)
{
	struct request *bp = malloc(sizeof(struct request));

	if (!bp)
		return NULL;

	memset(bp, 0, sizeof(struct request));
	bp->request = strdup(request);
	bp->offset = 0;
	bp->size = strlen(bp->request);
	bp->callback = callback;
	bp->udata = udata;

	return bp;
}

static void
request_free(struct request *req)
{
	if (req->request)
		free(req->request);

	free(req);
}

struct request *
bgpq_pipeline(struct bgpq_expander *b,
    int (*callback)(char *, struct bgpq_expander *, struct request *),
    void *udata, char *fmt, ...)
{
	char			 request[256];
	int			 ret;
	struct request	*bp = NULL;
	va_list			 ap;

	va_start(ap, fmt);
	vsnprintf(request, sizeof(request), fmt, ap);
	va_end(ap);

	SX_DEBUG(debug_expander,"expander: sending %s", request);

	bp = request_alloc(request, callback, udata);

	if (!bp) {
		sx_report(SX_FATAL,"Unable to allocate %lu bytes: %s\n",
		    (unsigned long)sizeof(struct request),
		    strerror(errno));
	}

	if (STAILQ_EMPTY(&b->wq)) {
		ret = write(b->fd, request, bp->size);
		if (ret < 0) {
			if (errno == EAGAIN) {
				STAILQ_INSERT_TAIL(&b->wq, bp, next);
				return bp;
			}
			sx_report(SX_FATAL, "Error writing request: %s\n",
			    strerror(errno));
		}
		bp->offset=ret;
		if (ret == bp->size) {
			STAILQ_INSERT_TAIL(&b->rq, bp, next);
		} else {
			STAILQ_INSERT_TAIL(&b->wq, bp, next);
		}
	} else
		STAILQ_INSERT_TAIL(&b->wq, bp, next);

	return bp;
}

static void
bgpq_expander_invalidate_asn(struct bgpq_expander *b, const char *q)
{
	char			*eptr;
	unsigned long		 asn = 0;
	struct asn_entry	 find, *res;

	if (!strncmp(q, "!gas", 4) || !strncmp(q, "!6as", 4)) {

		errno = 0;
		asn = strtoul(q + 4, &eptr, 10);
		if (*eptr != '\n') {
			sx_report(SX_ERROR, "not a number: %s\n", q);
			return;
		}
		if (errno == ERANGE && asn == ULONG_MAX) {
			sx_report(SX_ERROR, "overflow: %s\n", q);
			return;
		}
		if (asn == 0 || asn >= 4294967295) {
			sx_report(SX_ERROR, "out of range: %s\n", q);
			return;
		}
		if (eptr && *eptr != '\n') {
			sx_report(SX_ERROR, "no number? %s\n", q);
			return;
		}

		find.asn = asn;
		if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) == NULL) {
			RB_REMOVE(asn_tree, &b->asnlist, res);
			free(res);
		}
	}
}

static void
bgpq_write(struct bgpq_expander *b)
{
	while(!STAILQ_EMPTY(&b->wq)) {
		struct request *req = STAILQ_FIRST(&b->wq);

		int ret = write(b->fd, req->request + req->offset,
		    req->size-req->offset);

		if (ret < 0) {
			if (errno == EAGAIN)
				return;
			sx_report(SX_FATAL, "error writing data: %s\n",
			    strerror(errno));
		}

		if (ret == req->size - req->offset) {
			/* this request was dequeued */
			STAILQ_REMOVE_HEAD(&b->wq, next);
			STAILQ_INSERT_TAIL(&b->rq, req, next);
		} else {
			req->offset += ret;
			break;
		}
	}
}

static int
bgpq_selread(struct bgpq_expander *b, char *buffer, int size)
{
	fd_set		rfd, wfd;
	int		ret;

repeat:
	FD_ZERO(&rfd);
	FD_SET(b->fd, &rfd);
	FD_ZERO(&wfd);

	if (!STAILQ_EMPTY(&b->wq))
		FD_SET(b->fd, &wfd);

	ret = select(b->fd + 1, &rfd, &wfd, NULL, NULL);

	if (ret == 0)
		sx_report(SX_FATAL, "select failed\n");
	else if (ret == -1 && errno == EINTR)
		goto repeat;
	else if (ret == -1)
		sx_report(SX_FATAL, "select error %i: %s\n", errno,
		    strerror(errno));

	if (!STAILQ_EMPTY(&b->wq) && FD_ISSET(b->fd, &wfd))
		bgpq_write(b);

	if (FD_ISSET(b->fd, &rfd))
		return read(b->fd, buffer, size);

	goto repeat;
}

static int
bgpq_read(struct bgpq_expander *b)
{
	static char response[256];
	static int off = 0;
	int rval = 1;

	if (!STAILQ_EMPTY(&b->wq))
		bgpq_write(b);

	while(!STAILQ_EMPTY(&b->rq)) {
		int			 ret = 0;
		char			*cres;
		struct request	*req = STAILQ_FIRST(&b->rq);

		SX_DEBUG(debug_expander > 2, "waiting for answer to %s,"
		    "init %i '%.*s'\n", req->request, off, off, response);

		if ((cres=strchr(response, '\n')) != NULL)
			goto have;

repeat:
		ret = bgpq_selread(b, response + off, sizeof(response) - off);
		if (ret < 0) {
			if (errno == EAGAIN)
				goto repeat;
			sx_report(SX_FATAL,"Error reading data from IRRd: "
			    "%s (dequeue)\n", strerror(errno));
		} else if (ret == 0) {
			sx_report(SX_FATAL,"EOF from IRRd (dequeue)\n");
		}
		off += ret;

		if (!(cres = strchr(response, '\n')))
			goto repeat;

have:
		SX_DEBUG(debug_expander > 5, "got response of %.*s\n", off,
		    response);

		if (response[0] == 'A') {
			char		*eon, *c;
			unsigned long	 offset = 0;
			unsigned long 	 togot = strtoul(response + 1, &eon, 10);
			char 		*recvbuffer = malloc(togot + 2);

			if (!recvbuffer) {
				sx_report(SX_FATAL, "error allocating %lu "
				    "bytes: %s\n", togot + 2, strerror(errno));
			}

			memset(recvbuffer, 0, togot + 2);

			if (!eon || *eon != '\n') {
				sx_report(SX_ERROR,"A-code finished with wrong"
				    " char '%c'(%s)\n", eon ? *eon : '0',
				    response);
				exit(1);
			}

			if ((unsigned)(off - ((eon + 1) - response)) > togot) {
				// full response and more data is already in buffer
				memcpy(recvbuffer, eon + 1, togot);
				offset = togot;
				memmove(response, eon + 1 + togot,
				    off - ((eon + 1) - response) - togot);
				off -= togot + ((eon + 1) - response);
				memset(response + off, 0,
				    sizeof(response) - off);
			} else {
				/* response is not yet fully buffered */
				memcpy(recvbuffer, eon + 1,
				    off - ((eon + 1) - response));
				offset = off - ((eon + 1) - response);
				memset(response, 0, sizeof(response));
				off = 0;
			}

			SX_DEBUG(debug_expander > 5,
			    "starting read with ready '%.*s', waiting for "
			    "%lu\n", (int)offset, recvbuffer, togot - offset);

			if (off > 0)
				goto have3;
			if (offset == togot)
				goto reread2;

reread:

			ret = bgpq_selread(b, recvbuffer + offset, togot - offset);
			if (ret < 0) {
				if (errno == EAGAIN)
					goto reread;
				sx_report(SX_FATAL,"Error reading IRRd: %s "
				    "(dequeue, result)\n", strerror(errno));
			} else if (ret == 0) {
				sx_report(SX_FATAL,"EOF from IRRd (dequeue, "
				    "result)\n");
			}
			SX_DEBUG(debug_expander > 5,
				"Read1: got '%.*s'\n", ret,
				    recvbuffer + offset);
			offset += ret;
			if (offset < togot) {
				SX_DEBUG(debug_expander > 5, "expected %lu, got "
				    "%lu expanding %s", togot,
				    strlen(recvbuffer), req->request);
				goto reread;
			}

reread2:
			ret = bgpq_selread(b, response + off,
			    sizeof(response) - off);

			if (ret < 0) {
				if (errno == EAGAIN)
					goto reread2;
				sx_report(SX_FATAL,"Error reading IRRd: %s "
				    "(dequeue,final)\n", strerror(errno));
			} else if (ret == 0) {
				sx_report(SX_FATAL,"EOF from IRRd (dequeue,"
				    "final)\n");
			}

			SX_DEBUG(debug_expander > 5,
				"Read2: got '%.*s'\n", ret, response + off);

			off += ret;

have3:
			if (!(cres = strchr(response, '\n')))
				goto reread2;

			SX_DEBUG(debug_expander>=3,"Got %s (%lu bytes of %lu) "
			    "in response to %sfinal code: %.*s", recvbuffer,
			    strlen(recvbuffer), togot, req->request,
			    off, response);

			for (c = recvbuffer; c < recvbuffer + togot;) {
				size_t spn=strcspn(c," \n");
				if (spn)
					c[spn] = 0;
				if (c[0] == 0)
					break;
				if (!req->callback(c, b, req)) rval = 0;
				c += spn + 1;
			}
			assert(c == recvbuffer + togot);
			memset(recvbuffer, 0, togot + 2);
			free(recvbuffer);
		} else if (response[0] == 'C') {
			/* No data */
			SX_DEBUG(debug_expander,"No data expanding %s",
			    req->request);
			if (b->validate_asns)
				bgpq_expander_invalidate_asn(b, req->request);
		} else if (response[0] == 'D') {
			sx_report(SX_ERROR, "Key not found expanding %s",
			    req->request);
			if (b->validate_asns)
				bgpq_expander_invalidate_asn(b, req->request);
			rval = 0;
		} else if (response[0] == 'E') {
			sx_report(SX_ERROR, "Multiple keys expanding %s: %s",
			    req->request, response);
			rval = 0;
		} else if ( response[0] == 'F') {
			sx_report(SX_ERROR, "Error expanding %s: %s",
			    req->request, response);
			rval = 0;
		} else {
			sx_report(SX_ERROR,"Wrong reply: %s to %s", response,
			    req->request);
			exit(1);
		}

		memmove(response, cres + 1, off - ((cres + 1) - response));
		off -= (cres + 1) - response;
		memset(response + off, 0, sizeof(response) - off);
		SX_DEBUG(debug_expander > 5,
		    "fixed response of %i, %.*s\n", off, off, response);

		STAILQ_REMOVE_HEAD(&b->rq, next);
		b->piped--;

		request_free(req);
	}

	return rval;
}

int
bgpq_expand_irrd(struct bgpq_expander *b,
    int (*callback)(char *, struct bgpq_expander *, struct request *),
    void *udata, char *fmt, ...)
{
	char			 request[256], response[256];
	va_list			 ap;
	ssize_t			 ret;
	int			 off = 0;
	struct request	*req;
	int rval = 1;

	va_start(ap, fmt);
	vsnprintf(request, sizeof(request), fmt, ap);
	va_end(ap);

	req = request_alloc(request, callback, udata);

	SX_DEBUG(debug_expander, "expander sending: %s", request);

	if ((ret = write(b->fd, request, strlen(request)) == 0) || ret == -1) {
		sx_report(SX_ERROR,
			"Partial write of request to IRRd: %li bytes, %s\n",
			ret, strerror(errno));
		exit(1);
	}

	memset(response, 0, sizeof(response));

repeat:
	ret = bgpq_selread(b, response+off, sizeof(response)-off);
	if (ret < 0) {
		sx_report(SX_ERROR, "Error reading IRRd: %s\n",
		    strerror(errno));
		exit(1);
	} else if (ret == 0) {
		sx_report(SX_FATAL, "EOF reading IRRd\n");
	}

	off += ret;

	if (strchr(response, '\n') == NULL)
		goto repeat;

	SX_DEBUG(debug_expander > 2, "expander: initially got %lu bytes, "
	    "'%s'\n", (unsigned long)strlen(response), response);

	if (response[0] == 'A') {
		char	*eon, *c;
		long 	 togot = strtoul(response + 1, &eon, 10);
		char 	*recvbuffer = malloc(togot + 2);
		int 	 offset = 0;

		if (!recvbuffer) {
			sx_report(SX_FATAL, "Error allocating %lu bytes: %s\n",
			    togot + 2, strerror(errno));
		}

		if (eon && *eon != '\n') {
			sx_report(SX_ERROR,"A-code finished with wrong char "
			    "'%c' (%s)\n", *eon, response);
			exit(1);
		}

		if (off - ((eon + 1) - response) > togot) {
			memcpy(recvbuffer, eon + 1, togot);
			offset = togot;
			memmove(response, eon + 1 + togot,
			    off - ((eon + 1) - response) - togot);
			off -= togot + ((eon + 1) - response);
			memset(response+off, 0, sizeof(response) - off);
		} else {
			memcpy(recvbuffer, eon + 1,
			    off - ((eon + 1) - response));
			offset = off - ((eon + 1) - response);
			memset(response, 0, sizeof(response));
			off = 0;
		}

		if (off > 0)
			goto have3;
		if (offset == togot)
			goto reread2;

reread:
		ret = bgpq_selread(b, recvbuffer + offset, togot - offset);
		if (ret == 0) {
			sx_report(SX_FATAL,"EOF from IRRd (expand,result)\n");
		} else if (ret < 0) {
			sx_report(SX_FATAL,"Error reading IRRd: %s "
			    "(expand,result)\n", strerror(errno));
		}
		offset += ret;
		if (offset < togot)
			goto reread;

reread2:
		ret = bgpq_selread(b, response+off, sizeof(response) - off);
		if (ret < 0) {
			sx_report(SX_FATAL, "error reading IRRd: %s\n",
			    strerror(errno));
		} else if (ret == 0) {
			sx_report(SX_FATAL, "eof reading IRRd\n");
		}
		off += ret;

have3:
		if (!strchr(response, '\n'))
			goto reread2;

		SX_DEBUG(debug_expander > 2,"expander: final reply of %lu bytes,"
		    " %.*sreturn code %.*s",
		    (unsigned long)strlen(recvbuffer), offset, recvbuffer, off,
		    response);

		for (c = recvbuffer; c < recvbuffer + togot;) {
			size_t spn = strcspn(c, " \n");
			if (spn)
				c[spn] = 0;
			if (c[0] == 0)
				break;
			if (callback)
				if (!callback(c, b, req)) rval = 0;
			c += spn + 1;
		}
		memset(recvbuffer, 0, togot + 2);
		free(recvbuffer);
	} else if (response[0] == 'C') {
		/* no data */
		if (b->validate_asns)
			bgpq_expander_invalidate_asn(b, request);
	} else if (response[0] == 'D') {
		sx_report(SX_ERROR, "Key not found expanding %s",
			req->request);
		if (b->validate_asns)
			bgpq_expander_invalidate_asn(b, request);
		rval = 0;
	} else if (response[0] == 'E') {
		/* XXXXXX */
	} else if (response[0] == 'F') {
		sx_report(SX_ERROR, "Error expanding %s: %s",
			request, response);
		rval = 0;
	} else {
		sx_report(SX_ERROR,"Wrong reply: %s", response);
		exit(1);
	}
	request_free(req);

	return rval;
}

int
bgpq_expand(struct bgpq_expander *b)
{
	int			 fd = -1, err, ret, aquery = 0;
	struct slentry		*mc;
	struct addrinfo 	 hints, *res = NULL, *rp;
	struct linger		 sl;
	struct asn_entry	*asne;

	sl.l_onoff = 1;
	sl.l_linger = 5;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_socktype = SOCK_STREAM;

	err=getaddrinfo(b->server, b->port, &hints, &res);

	if (err) {
		sx_report(SX_ERROR,"Unable to resolve %s: %s\n", b->server,
		    gai_strerror(err));
		exit(1);
	}

	for (rp=res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, 0);
		if (fd == -1) {
			if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
				continue;
			sx_report(SX_ERROR,"Unable to create socket: %s\n",
			    strerror(errno));
			exit(1);
		}
		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl,
		    sizeof(struct linger))) {
			sx_report(SX_ERROR,"Unable to set linger on socket: "
			    "%s\n", strerror(errno));
			close(fd);
			exit(1);
		}
		err = connect(fd, rp->ai_addr, rp->ai_addrlen);
		if (err) {
			close(fd);
			fd = -1;
			continue;
		}
		err = sx_maxsockbuf(fd, SO_SNDBUF);
		if (err > 0) {
			SX_DEBUG(debug_expander, "Acquired sendbuf of %i "
			    "bytes\n", err);
		} else {
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(res);

	if (fd == -1) {
		/* all our attempts to connect failed */
		sx_report(SX_ERROR,"All attempts to connect %s failed, last"
		    " error: %s\n", b->server, strerror(errno));
		exit(1);
	}

	b->fd = fd;

	SX_DEBUG(debug_expander, "Sending '!!' to server to request for the"
	    " connection to remain open\n");
	if ((ret = write(fd, "!!\n", 3)) != 3) {
		sx_report(SX_ERROR, "Partial write of multiple command mode "
		    "to IRRd: %i bytes, %s\n", ret, strerror(errno));
		close(fd);
		exit(1);
	}

	if (b->identify) {
		SX_DEBUG(debug_expander, "b->identify: Sending '!n "
		    PACKAGE_STRING "' to server.\n");
		char ident[128];
		int ilen = snprintf(ident, sizeof(ident), "!n" PACKAGE_STRING "\n");
		if (ilen > 0) {
			if ((ret = write(fd, ident, ilen)) != ilen) {
				sx_report(SX_ERROR, "Partial write of "
				    "identifier to IRRd: %i bytes, %s\n",
				    ret, strerror(errno));
				close(fd);
				exit(1);
			}
			memset(ident, 0, sizeof(ident));
			if (0 < read(fd, ident, sizeof(ident))) {
				SX_DEBUG(debug_expander, "Got answer %s", ident);
			} else {
				sx_report(SX_ERROR, "ident, failed read from IRRd\n");
				close(fd);
				exit(1);
			}
		} else {
			sx_report(SX_ERROR, "snprintf(ident) failed\n");
			close(fd);
			exit(1);
		}
	}

	/* Test whether the server has support for the A query */
	if (b->generation >= T_PREFIXLIST && !STAILQ_EMPTY(&b->macroses)) {
		char aret[128];
		char aresp[] = "F Missing required set name for A query";
		SX_DEBUG(debug_expander, "Testing support for A queries\n");
		if ((ret = write(fd, "!a\n", 3)) != 3) {
			sx_report(SX_ERROR, "Partial write of '!a' test query "
			    "to IRRd: %i bytes, %s\n", ret, strerror(errno));
			close(fd);
			exit(1);
		}
		memset(aret, 0, sizeof(aret));
		if (0 < read(fd, aret, sizeof(aret))) {
			if (strncmp(aret, aresp, strlen(aresp)) == 0) {
				SX_DEBUG(debug_expander, "Server supports A query\n");
				aquery = 1;
			} else {
				SX_DEBUG(debug_expander, "No support for A query\n");
			}
		} else {
			sx_report(SX_ERROR, "A query test failed read from IRRd\n");
			close(fd);
			exit(1);
		}
	}

	if (b->usesource) {
		if (b->sources && b->sources[0] != 0) {
			b->defaultsources = (char*)calloc(1, strlen(b->sources));
			strcpy(b->defaultsources, b->sources);
		} else {
			b->defaultsources = bgpq_get_irrd_sources(b->fd);
		}
	} else {
		b->defaultsources = bgpq_get_irrd_sources(b->fd);
	}

	if (b->sources && b->sources[0] != 0) {
		int slen = strlen(b->sources) + 4;
		if (slen < 256)
			slen = 256;
		char sources[slen];
		slen = snprintf(sources, sizeof(sources), "!s%s\n", b->sources);
		if (slen > 0) {
			SX_DEBUG(debug_expander, "Requesting sources %s", sources);
			if ((ret = write(fd, sources, slen)) != slen) {
				sx_report(SX_ERROR, "Partial write of sources to "
				    "IRRd: %i bytes, %s\n", ret, strerror(errno));
				close(fd);
				exit(1);
			}
			memset(sources, 0, sizeof(sources));
			if (0 < read(fd, sources, sizeof(sources))) {
				SX_DEBUG(debug_expander, "Got answer %s", sources);
				if (sources[0] != 'C') {
					sx_report(SX_ERROR, "Invalid source(s) "
					    "'%s': %s\n", b->sources, sources);
					close(fd);
					exit(1);
				}
			} else {
				sx_report(SX_ERROR, "failed to read sources\n");
				close(fd);
				exit(1);
			}
		} else {
			sx_report(SX_ERROR, "snprintf(sources) failed\n");
			close(fd);
			exit(1);
		}
	}

	if (pipelining)
		fcntl(fd, F_SETFL, O_NONBLOCK|(fcntl(fd, F_GETFL)));

	STAILQ_FOREACH(mc, &b->macroses, entry) {
		if (!b->maxdepth && RB_EMPTY(&b->stoplist)) {
			if (b->usesource) {
				char *source = bgpq_get_source(mc->text);
				if (source){
					if (pipelining){
						bgpq_pipeline(b, NULL, NULL, "!s%s\n", source);
						bgpq_pipeline(b, bgpq_expanded_macro_limit, b,
							"!i%s\n", bgpq_get_asset(mc->text));
					} else {
						bgpq_expand_irrd(b, NULL, NULL, "!s%s\n", source);
						bgpq_expand_irrd(b, bgpq_expanded_macro_limit,
							b, "!i%s\n", bgpq_get_asset(mc->text));
					}
					free(source);
				} else {
					if (pipelining){
						bgpq_pipeline(b, NULL, NULL, "!s%s\n",
							b->defaultsources);
						bgpq_pipeline(b, bgpq_expanded_macro_limit, b,
							"!i%s\n", bgpq_get_asset(mc->text));
					} else {
						bgpq_expand_irrd(b, NULL, NULL, "!s%s\n",
							b->defaultsources);
						bgpq_expand_irrd(b, bgpq_expanded_macro_limit, b,
							"!i%s\n", bgpq_get_asset(mc->text));
					}
				}
			} else if (aquery)
				bgpq_expand_irrd(b, bgpq_expanded_prefix, b,
				    "!a%s%s\n",
				    b->family == AF_INET ? "4" : "6",
				    bgpq_get_asset(mc->text));
			else
				bgpq_expand_irrd(b, bgpq_expanded_macro, b,
				    "!i%s,1\n", bgpq_get_asset(mc->text));
		} else {
			bgpq_expander_add_already(b, bgpq_get_asset(mc->text));
			if (pipelining)
				bgpq_pipeline(b, bgpq_expanded_macro_limit,
				    NULL, "!i%s\n", bgpq_get_asset(mc->text));
			else
				bgpq_expand_irrd(b, bgpq_expanded_macro_limit,
				    NULL, "!i%s\n", bgpq_get_asset(mc->text));
		}
	}

	if (pipelining){
		bgpq_pipeline(b, NULL, NULL, "!s%s\n", b->defaultsources);
	} else {
		bgpq_expand_irrd(b, NULL, NULL, "!s%s\n", b->defaultsources);
	}

	if (pipelining) {
		if (!STAILQ_EMPTY(&b->wq))
			bgpq_write(b);
		if (!STAILQ_EMPTY(&b->rq))
			bgpq_read(b);
	}

	if (b->generation >= T_PREFIXLIST || b->validate_asns) {
		STAILQ_FOREACH(mc, &b->rsets, entry) {
			if (b->usesource) {
				char *source = bgpq_get_source(mc->text);
				if (source){
					if (pipelining){
						printf("Checking %s\n", bgpq_get_rset(mc->text));
						bgpq_pipeline(b, NULL, NULL, "!s%s\n", source);
						if (b->family == AF_INET)
							bgpq_pipeline(b, bgpq_expanded_prefix,
				    			NULL, "!i%s\n", bgpq_get_rset(mc->text));
						else
							bgpq_pipeline(b, bgpq_expanded_v6prefix,
								NULL, "!i%s\n", bgpq_get_rset(mc->text));
					} else {
						bgpq_expand_irrd(b, NULL, NULL, "!s%s\n", source);
						if (b->family == AF_INET)
							bgpq_expand_irrd(b, bgpq_expanded_prefix,
				    			NULL, "!i%s\n", bgpq_get_rset(mc->text));
						else
							bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
								NULL, "!i%s\n", bgpq_get_rset(mc->text));
					}
					free(source);
				} else {
					if (pipelining){
						bgpq_pipeline(b, NULL, NULL, "!s%s\n",
							b->defaultsources);
						if (b->family == AF_INET)
							bgpq_pipeline(b, bgpq_expanded_prefix,
								NULL, "!i%s\n", bgpq_get_rset(mc->text));
						else
							bgpq_pipeline(b, bgpq_expanded_v6prefix,
								NULL, "!i%s\n", bgpq_get_rset(mc->text));
					} else {
						bgpq_expand_irrd(b, NULL, NULL, "!s%s\n",
							b->defaultsources);
						if (b->family == AF_INET)
							bgpq_expand_irrd(b, bgpq_expanded_prefix,
								NULL, "!i%s\n", bgpq_get_rset(mc->text));
						else
							bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
								NULL, "!i%s\n", bgpq_get_rset(mc->text));
					}
				}
			} else {
				if (pipelining){
					bgpq_pipeline(b, NULL, NULL, "!s%s\n",
						b->defaultsources);
					if (b->family == AF_INET)
						bgpq_pipeline(b, bgpq_expanded_prefix,
							NULL, "!i%s,1\n", bgpq_get_rset(mc->text));
					else
						bgpq_pipeline(b, bgpq_expanded_v6prefix,
							NULL, "!i%s,1\n", bgpq_get_rset(mc->text));
				} else {
					bgpq_expand_irrd(b, NULL, NULL, "!s%s\n",
						b->defaultsources);
					if (b->family == AF_INET)
						bgpq_expand_irrd(b, bgpq_expanded_prefix,
							NULL, "!i%s,1\n", bgpq_get_rset(mc->text));
					else
						bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
							NULL, "!i%s,1\n", bgpq_get_rset(mc->text));
				}
			}
		}

		RB_FOREACH(asne, asn_tree, &b->asnlist) {
			if (b->family == AF_INET6) {
				if (!pipelining) {
					bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
					    NULL, "!6as%" PRIu32 "\n", asne->asn);
				} else {
					bgpq_pipeline(b, bgpq_expanded_v6prefix,
					    NULL, "!6as%" PRIu32 "\n", asne->asn);
				}
			} else {
				if (!pipelining) {
					bgpq_expand_irrd(b, bgpq_expanded_prefix,
					    NULL, "!gas%" PRIu32 "\n", asne->asn);
				} else {
					bgpq_pipeline(b, bgpq_expanded_prefix,
					    NULL, "!gas%" PRIu32 "\n", asne->asn);
				}
			}
		}

		if (pipelining) {
			if (!STAILQ_EMPTY(&b->wq))
				bgpq_write(b);
			if (!STAILQ_EMPTY(&b->rq))
				bgpq_read(b);
		}
	}

	if ((ret = write(fd, "!q\n", 3)) != 3) {
		sx_report(SX_ERROR, "Partial write of quit to IRRd: %i bytes, %s\n",
		    ret, strerror(errno));
		// not worth exiting due to this
	}
	if (pipelining) {
		int fl = fcntl(fd, F_GETFL);
		fl &= ~O_NONBLOCK;
		fcntl(fd, F_SETFL, fl);
	}
	close(fd);
	free(b->defaultsources);

	return 1;
}

void
sx_radix_node_freeall(struct sx_radix_node *n) {

	if (n->l != NULL)
		sx_radix_node_freeall(n->l);

	if (n->r != NULL)
		sx_radix_node_freeall(n->r);

	if (n->son != NULL)
		sx_radix_node_freeall(n->son);

	if (n->payload)
		free(n->payload);

	sx_prefix_free(n->prefix);

	free(n);
}

void
sx_radix_tree_freeall(struct sx_radix_tree *t) {

	if (t->head != NULL)
		sx_radix_node_freeall(t->head);

	free(t);
}

void
bgpq_prequest_freeall(struct bgpq_prequest *bpr) {
}

void
expander_freeall(struct bgpq_expander *expander) {
	struct sx_tentry	*var, *nxt;
	struct asn_entry	*asne, *asne_next;

	while (!STAILQ_EMPTY(&expander->macroses)) {
		struct slentry *n1 = STAILQ_FIRST(&expander->macroses);
		STAILQ_REMOVE_HEAD(&expander->macroses, entry);
		free(n1->text);
		free(n1);
	}

	while (!STAILQ_EMPTY(&expander->rsets)) {
		struct slentry *n1 = STAILQ_FIRST(&expander->rsets);
		STAILQ_REMOVE_HEAD(&expander->rsets, entry);
		free(n1->text);
		free(n1);
	}

	for (var = RB_MIN(tentree, &expander->already); var != NULL; var = nxt) {
		nxt = RB_NEXT(tentree, &expander->already, var);
		RB_REMOVE(tentree, &expander->already, var);
		free(var->text);
		free(var);
	}

	for (var = RB_MIN(tentree, &expander->stoplist); var != NULL; var = nxt) {
		nxt = RB_NEXT(tentree, &expander->stoplist, var);
		RB_REMOVE(tentree, &expander->stoplist, var);
		free(var->text);
		free(var);
	}

	for (asne = RB_MIN(asn_tree, &expander->asnlist);
	    asne != NULL; asne = asne_next) {
		asne_next = RB_NEXT(asn_tree, &expander->asnlist, asne);
		RB_REMOVE(asn_tree, &expander->asnlist, asne);
		free(asne);
	}

	sx_radix_tree_freeall(expander->tree);

	bgpq_prequest_freeall(expander->firstpipe);
	bgpq_prequest_freeall(expander->lastpipe);
}
