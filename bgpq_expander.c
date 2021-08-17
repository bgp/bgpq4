/*
 * Copyright (c) 2019-2021 Job Snijders <job@sobornost.net>
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
#include <fcntl.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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
	b->name = "NN";
	b->aswidth = 8;
	b->asn32s[0] = malloc(8192);
	if (!b->asn32s[0]) {
		sx_report(SX_FATAL,"Unable to allocate 8192 bytes: %s\n",
		    strerror(errno));
		exit(1);
	}
	memset(b->asn32s[0], 0, 8192);
	b->identify = 1;
	b->server = "rr.ntt.net";
	b->port = "43";

	//	b->wq = STAILQ_HEAD_INITIALZIER(b->wq);
	//      b->rq = STAILQ_HEAD_INITIALZIER(b->rq);
	//      b->rsets = STAILQ_HEAD_INITIALZIER(b->rsets);
	//      b->macroses = STAILQ_HEAD_INITIALZIER(b->macroses);
	
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
	struct sx_slentry	*le;

	if (!b || !as)
		return 0;

	le = sx_slentry_new(as);

	STAILQ_INSERT_TAIL(&b->macroses, le, next);

	return 1;
}

int
bgpq_expander_add_rset(struct bgpq_expander *b, char *rs)
{
	struct sx_slentry	*le;

	if (!b || !rs)
		return 0;

	le = sx_slentry_new(rs);

	if (!le)
		return 0;

	STAILQ_INSERT_TAIL(&b->rsets, le, next);

	return 1;
}

static int
bgpq_expander_add_already(struct bgpq_expander *b, char *rs)
{
	struct sx_tentry	*le, lkey;

	lkey.text = rs;

	if (RB_FIND(tentree, &b->already, &lkey))
		return 1;

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
		return 1;

	le = sx_tentry_new(rs);

	RB_INSERT(tentree, &b->stoplist, le);

	return 1;
}

int
bgpq_expander_add_as(struct bgpq_expander *b, char *as)
{
	char		*eoa;
	uint32_t	 asn1 = 0, asn2 = 0;
	uint32_t	 asno = 0;

	if (!b || !as)
		return 0;

	asno = strtoul(as + 2, &eoa, 10);

	if (eoa && *eoa != 0) {
		sx_report(SX_ERROR,"Invalid symbol in AS number: '%c' in %s\n",
		    *eoa, as);
		return 0;
	}

	if (asno > 65535) {
		asn1 = asno / 65536;
		asn2 = asno % 65536;
	} else
		asn1 = asno;

	if (!expand_special_asn &&
	    ((asno  >= 4200000000ul) || (asno >= 64496 && asno <= 65551)))
		return 0;

	if (!b->asn32s[asn1]) {
		b->asn32s[asn1] = malloc(8192);
		if (!b->asn32s[asn1]) {
			sx_report(SX_FATAL, "Unable to allocate 8192 "
			    "bytes: %s. Unable to add asn32 %s to "
			    " future expansion\n", strerror(errno), as);
				return 0;
			}
		memset(b->asn32s[asn1], 0, 8192);
	}

	if (asno > 65535)
		b->asn32s[asn1][asn2 / 8] |= (0x80 >> (asn2 % 8));
	else
		b->asn32s[0][asn1 / 8] |= (0x80 >> (asn1 % 8));

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
		sx_prefix_destroy(p);

	return 1;
}

int
bgpq_expander_add_prefix_range(struct bgpq_expander *b, char *prefix)
{
	return sx_prefix_range_parse(b->tree, b->family, b->maxlen, prefix);
}

static int
bgpq_expanded_macro(char *as, struct bgpq_expander *ex,
    struct bgpq_request *req)
{
	bgpq_expander_add_as(ex, as);

	return 1;
}

struct bgpq_request *bgpq_pipeline(struct bgpq_expander *b,
	int (*callback)(char*, struct bgpq_expander *b, struct bgpq_request *req),
	void *udata, char *fmt, ...);
int bgpq_expand_irrd(struct bgpq_expander *b,
    int (*callback)(char*, struct bgpq_expander *b, struct bgpq_request *req),
     void *udata, char *fmt, ...);

static int
bgpq_expanded_macro_limit(char *as, struct bgpq_expander *b,
    struct bgpq_request *req)
{
	if (!strncasecmp(as, "AS-", 3) || strchr(as, '-') || strchr(as, ':')) {
		struct sx_tentry tkey = { .text = as };

		if (RB_FIND(tentree, &b->already, &tkey)) {
			SX_DEBUG(debug_expander>2, "%s is already expanding, "
			    "ignore\n", as);
			return 0;
		}

		if (RB_FIND(tentree, &b->stoplist, &tkey)) {
			SX_DEBUG(debug_expander>2, "%s is in the stoplist, "
			    "ignore\n", as);
			return 0;
		}

		if (!b->maxdepth ||
		    (b->cdepth + 1 < b->maxdepth &&
		    req->depth + 1 < b->maxdepth)) {
			bgpq_expander_add_already(b, as);
			if (pipelining) {
				struct bgpq_request *req1 = bgpq_pipeline(b,
				    bgpq_expanded_macro_limit, NULL, "!i%s\n",
				    as);
				req1->depth = req->depth+1;
			} else {
				b->cdepth++;
				bgpq_expand_irrd(b, bgpq_expanded_macro_limit,
				    NULL, "!i%s\n", as);
				b->cdepth--;
			}
		} else {
			SX_DEBUG(debug_expander>2, "ignoring %s at depth %i\n",
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
    struct bgpq_request *req __attribute__((unused)))
{
	char *d = strchr(as, '^');

	if (!d)
		bgpq_expander_add_prefix(ex, as);
	else
		bgpq_expander_add_prefix_range(ex, as);

	return 1;
}

static int
bgpq_expanded_v6prefix(char *prefix, struct bgpq_expander * ex,
    struct bgpq_request* req)
{
	char *d = strchr(prefix, '^');

	if (!d)
		bgpq_expander_add_prefix(ex, prefix);
	else
		bgpq_expander_add_prefix_range(ex, prefix);

	return 1;
}

int bgpq_pipeline_dequeue(int fd, struct bgpq_expander *b);

static struct bgpq_request*
bgpq_request_alloc(char *request, int (*callback)(char*, struct bgpq_expander*,
    struct bgpq_request*), void* udata)
{
	struct bgpq_request* bp = malloc(sizeof(struct bgpq_request));

	if (!bp)
		return NULL;

	memset(bp, 0, sizeof(struct bgpq_request));
	bp->request = strdup(request);
	bp->offset = 0;
	bp->size = strlen(bp->request);
	bp->callback = callback;
	bp->udata = udata;

	return bp;
}

static void
bgpq_request_free(struct bgpq_request* req)
{
	if (req->request)
		free(req->request);

	free(req);
}

struct bgpq_request*
bgpq_pipeline(struct bgpq_expander *b,
    int (*callback)(char*, struct bgpq_expander*, struct bgpq_request*),
    void* udata, char *fmt, ...)
{
	char request[128];
	int ret;
	struct bgpq_request* bp = NULL;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(request, sizeof(request), fmt, ap);
	va_end(ap);

	SX_DEBUG(debug_expander,"expander: sending %s", request);

	bp = bgpq_request_alloc(request, callback, udata);

	if (!bp) {
		sx_report(SX_FATAL,"Unable to allocate %lu bytes: %s\n",
		    (unsigned long)sizeof(struct bgpq_request),
		    strerror(errno));
		exit(1);
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
	if (!strncmp(q, "!gas", 4) || !strncmp(q, "!6as", 4)) {
		char *eptr;
		unsigned long asn = strtoul(q+4, &eptr, 10), asn0, asn1 = 0;
		if (!asn || asn == ULONG_MAX || asn >= 4294967295
		    || (eptr && *eptr != '\n')) {
			sx_report(SX_ERROR, "some problem invalidating asn"
			    " %s\n", q);
			return;
		}
		asn1 = asn % 65536;
		asn0 = asn / 65536;
		if (!b->asn32s[asn0] ||
		    !(b->asn32s[asn0][asn1/8] & (0x80 >> (asn1 % 8)))) {
			sx_report(SX_NOTICE, "strange, invalidating inactive "
			    "asn %lu(%s)\n", asn, q);
		} else {
			b->asn32s[asn0][asn1 / 8] &= ~(0x80 >> (asn1 % 8));
		}
	}
}

static void
bgpq_write(struct bgpq_expander *b)
{
	while(!STAILQ_EMPTY(&b->wq)) {
		struct bgpq_request* req = STAILQ_FIRST(&b->wq);

		int ret = write(b->fd, req->request+req->offset,
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
	fd_set rfd, wfd;
	int ret;

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

	if (!STAILQ_EMPTY(&b->wq))
		bgpq_write(b);

	while(!STAILQ_EMPTY(&b->rq)) {
		struct bgpq_request* req = STAILQ_FIRST(&b->rq);
		SX_DEBUG(debug_expander > 2, "waiting for answer to %s,"
		    "init %i '%.*s'\n", req->request, off, off, response);
		int ret = 0;
		char *cres;

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

			memset(recvbuffer,0,togot+2);

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
				offset = off - ((eon+1) - response);
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
				SX_DEBUG(debug_expander>5, "expected %lu, got "
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
				req->callback(c, b, req);
				c += spn+1;
			}
			assert(c == recvbuffer + togot);
			memset(recvbuffer, 0, togot + 2);
			free(recvbuffer);
		} else if (response[0] == 'C') {
			/* No data */
			SX_DEBUG(debug_expander,"No data expanding %s\n",
			    req->request);
			if (b->validate_asns)
				bgpq_expander_invalidate_asn(b, req->request);
		} else if (response[0] == 'D') {
			/* .... */
			SX_DEBUG(debug_expander,"Key not found expanding %s\n",
			    req->request);
			if (b->validate_asns)
				bgpq_expander_invalidate_asn(b, req->request);
		} else if (response[0] == 'E') {
			sx_report(SX_ERROR, "Multiple keys expanding %s: %s\n",
			    req->request, response);
		} else if ( response[0] == 'F') {
			sx_report(SX_ERROR, "Error expanding %s: %s\n",
			    req->request, response);
		} else {
			sx_report(SX_ERROR,"Wrong reply: %s to %s\n", response,
			    req->request);
			exit(1);
		}

		memmove(response, cres + 1, off - ((cres + 1) - response));
		off -= (cres+1) - response;
		memset(response + off, 0, sizeof(response) - off);
		SX_DEBUG(debug_expander > 5,
		    "fixed response of %i, %.*s\n", off, off, response);

		STAILQ_REMOVE_HEAD(&b->rq, next);
		b->piped--;

		bgpq_request_free(req);
	}

	return 0;
}

int
bgpq_expand_irrd(struct bgpq_expander *b,
    int (*callback)(char*, struct bgpq_expander*, struct bgpq_request* ),
    void* udata, char *fmt, ...)
{
	char			 request[128], response[128];
	va_list			 ap;
	size_t			 ret;
	int			 off = 0;
	struct bgpq_request	*req;

	va_start(ap, fmt);
	vsnprintf(request, sizeof(request), fmt, ap);
	va_end(ap);

	req = bgpq_request_alloc(request, callback, udata);

	SX_DEBUG(debug_expander, "expander: sending '%s'\n", request);

	ret=write(b->fd, request, strlen(request));
	if (ret != strlen(request)) {
		sx_report(SX_FATAL,"Partial write to IRRd, only %lu bytes "
		    "written: %s\n", ret, strerror(errno));
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
		exit(1);
	}

	off += ret;

	if (strchr(response, '\n') == NULL)
		goto repeat;

	SX_DEBUG(debug_expander > 2, "expander: initially got %lu bytes, "
	    "'%s'\n", (unsigned long)strlen(response), response);

	if (response[0] == 'A') {
		char	*eon, *c;
		long 	 togot = strtoul(response+1, &eon, 10);
		char 	*recvbuffer = malloc(togot + 2);
		int 	 offset = 0;

		if (!recvbuffer) {
			sx_report(SX_FATAL, "Error allocating %lu bytes: %s\n",
			    togot + 2, strerror(errno));
		}

		if (eon && *eon != '\n') {
			sx_report(SX_ERROR,"A-code finised with wrong char "
			    "'%c' (%s)\n", *eon, response);
			exit(1);
		}

		if (off - ((eon + 1)-response) > togot) {
			memcpy(recvbuffer, eon+1, togot);
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
			exit(1);
		} else if (ret == 0) {
			sx_report(SX_FATAL, "eof reading IRRd\n");
			exit(1);
		}
		off += ret;

have3:
		if (!strchr(response, '\n'))
			goto reread2;

		SX_DEBUG(debug_expander>2,"expander: final reply of %lu bytes,"
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
				callback(c, b, req);
			c += spn + 1;
		}
		memset(recvbuffer, 0, togot + 2);
		free(recvbuffer);
	} else if (response[0] == 'C') {
		/* no data */
		if (b->validate_asns)
			bgpq_expander_invalidate_asn(b, request);
	} else if (response[0] == 'D') {
		/* ... */
		if (b->validate_asns)
			bgpq_expander_invalidate_asn(b, request);
	} else if (response[0] == 'E') {
		/* XXXXXX */
	} else if (response[0] == 'F') {
		/* XXXXXX */
	} else {
		sx_report(SX_ERROR,"Wrong reply: %s\n", response);
		exit(0);
	}
	bgpq_request_free(req);

	return 0;
}

int
bgpq_expand(struct bgpq_expander *b)
{
	int			 fd = -1, err, ret, aquery = 0;
	struct sx_slentry	*mc;
	struct addrinfo 	 hints, *res = NULL, *rp;
	struct linger		 sl;

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
	    "connection to remain open\n");
	if ((ret = write(fd, "!!\n", 3)) != 3) {
		sx_report(SX_ERROR, "Partial write of multiple command mode "
		    "to IRRd: %i bytes, %s\n", ret, strerror(errno));
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
				exit(1);
			}
			memset(ident, 0, sizeof(ident));
			if (0 < read(fd, ident, sizeof(ident))) {
				SX_DEBUG(debug_expander, "Got answer %s", ident);
			} else {
				sx_report(SX_ERROR, "ident, failed read from IRRd\n");
				exit(1);
			}
		} else {
			sx_report(SX_ERROR, "snprintf(ident) failed\n");
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
			exit(1);
		}
	}

	if (b->sources && b->sources[0] != 0) {
		int slen = strlen(b->sources) + 4;
		if (slen < 128)
			slen = 128;
		char sources[slen];
		slen = snprintf(sources, sizeof(sources), "!s%s\n", b->sources);
		if (slen > 0) {
			SX_DEBUG(debug_expander, "Requesting sources %s", sources);
			if ((ret = write(fd, sources, slen)) != slen) {
				sx_report(SX_ERROR, "Partial write of sources to "
				    "IRRd: %i bytes, %s\n", ret, strerror(errno));
				exit(1);
			}
			memset(sources, 0, sizeof(sources));
			if (0 < read(fd, sources, sizeof(sources))) {
				SX_DEBUG(debug_expander, "Got answer %s", sources);
				if (sources[0] != 'C') {
					sx_report(SX_ERROR, "Invalid source(s) "
					    "'%s': %s\n", b->sources, sources);
					exit(1);
				}
			} else {
				sx_report(SX_ERROR, "failed to read sources\n");
				exit(1);
			}
		} else {
			sx_report(SX_ERROR, "snprintf(sources) failed\n");
			exit(1);
		}
	}

	if (pipelining)
		fcntl(fd, F_SETFL, O_NONBLOCK|(fcntl(fd, F_GETFL)));

	STAILQ_FOREACH(mc, &b->macroses, next) {
		if (!b->maxdepth && RB_EMPTY(&b->stoplist)) {
			if (aquery)
				bgpq_expand_irrd(b, bgpq_expanded_prefix, b,
				    "!a%s%s\n",
				    b->family == AF_INET ? "4" : "6",
				    mc->text);
			else
				bgpq_expand_irrd(b, bgpq_expanded_macro, b,
				    "!i%s,1\n", mc->text);
		} else {
			bgpq_expander_add_already(b, mc->text);
			if (pipelining)
				bgpq_pipeline(b, bgpq_expanded_macro_limit,
				    NULL, "!i%s\n", mc->text);
			else
				bgpq_expand_irrd(b, bgpq_expanded_macro_limit,
				    NULL, "!i%s\n", mc->text);
		}
	}

	if (pipelining) {
		if (!STAILQ_EMPTY(&b->wq))
			bgpq_write(b);
		if (!STAILQ_EMPTY(&b->rq))
			bgpq_read(b);
	}

	if (b->generation >= T_PREFIXLIST || b->validate_asns) {
		uint32_t i, j, k;
		STAILQ_FOREACH(mc, &b->rsets, next) {
			if (b->family == AF_INET)
				bgpq_expand_irrd(b, bgpq_expanded_prefix,
				    NULL, "!i%s,1\n", mc->text);
			else
				bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
				    NULL, "!i%s,1\n", mc->text);
		}
		for (k=0; k < sizeof(b->asn32s) / sizeof(unsigned char*); k++) {
			if (!b->asn32s[k])
				continue;
			for (i=0; i<8192; i++) {
				for (j=0; j<8; j++) {
					if (b->asn32s[k][i] & (0x80 >> j)) {
						if (b->family == AF_INET6) {
							if (!pipelining) {
								bgpq_expand_irrd(b, bgpq_expanded_v6prefix,
								    NULL, "!6as%" PRIu32 "\n", ( k << 16) + i * 8 + j);
							} else {
								bgpq_pipeline(b, bgpq_expanded_v6prefix,
								    NULL, "!6as%" PRIu32 "\n", (k << 16) + i * 8 + j);
							}
						} else {
							if (!pipelining) {
								bgpq_expand_irrd(b, bgpq_expanded_prefix,
								    NULL, "!gas%" PRIu32 "\n", (k << 16) + i * 8 + j);
							} else {
								bgpq_pipeline(b, bgpq_expanded_prefix,
								    NULL, "!gas%" PRIu32 "\n", ( k<< 16) + i* 8 + j);
							}
						}
					}
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

	return 1;
}

