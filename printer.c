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

#include <sys/tree.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "extern.h"
#include "sx_report.h"

extern int debug_expander;

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

static void 
bgpq4_print_cisco_aspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "no ip as-path access-list %s\n", b->name);

	if (RB_EMPTY(&b->asnlist)) {
		fprintf(f, "ip as-path access-list %s deny .*\n", b->name);
		return;
	}

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "ip as-path access-list %s permit ^%u(_%u)*$\n",
		    b->name, res->asn, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc)
			fprintf(f, "ip as-path access-list %s permit"
			    " ^%u(_[0-9]+)*_(%u", b->name, b->asnumber,
			    asne->asn);
		else
			fprintf(f,"|%u", asne->asn);

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, ")$\n");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f,")$\n");
}

static void
bgpq4_print_cisco_xr_aspath(FILE *f, struct bgpq_expander *b)
{
	int 			 nc = 0, comma = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "as-path-set %s", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "\n  ios-regex '^%u(_%u)*$'", res->asn, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		comma = 1;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f, "%s\n  ios-regex '^%u(_[0-9]+)*_(%u",
			    comma ? "," : "",
			    b->asnumber,
			    asne->asn);
			comma = 1;
		} else
			fprintf(f, "|%u", asne->asn);

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, ")$'");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f, ")$'");

	fprintf(f, "\nend-set\n");
}

static void
bgpq4_print_cisco_oaspath(FILE *f, struct bgpq_expander *b)
{
	int 			 nc = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "no ip as-path access-list %s\n", b->name);

	if (RB_EMPTY(&b->asnlist)) {
		fprintf(f, "ip as-path access-list %s deny .*\n", b->name);
		return;
	}

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "ip as-path access-list %s permit ^(_%u)*$\n",
		    b->name, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc)
			fprintf(f,"ip as-path access-list %s permit"
			    " ^(_[0-9]+)*_(%u", b->name, asne->asn);
		else
			fprintf(f,"|%u",asne->asn);

		nc++;
		if (nc == b->aswidth) {
			fprintf(f,")$\n");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f, ")$\n");

}

static void
bgpq4_print_cisco_xr_oaspath(FILE *f, struct bgpq_expander *b)
{
	int 			 nc = 0, comma = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "as-path-set %s", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "\n  ios-regex '^(_%u)*$'", res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		comma = 1;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f,"%s\n  ios-regex '^(_[0-9]+)*_(%u",
			    comma ? "," : "", asne->asn);
			comma = 1;
		} else
			fprintf(f,"|%u",asne->asn);

		nc++;
		if (nc == b->aswidth) {
			fprintf(f,")$'");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f,")$'");

	fprintf(f,"\nend-set\n");
}

static void
bgpq4_print_juniper_aspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0, lineNo = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n",
	    b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "  as-path a0 \"^%u(%u)*$\";\n", res->asn, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		lineNo++;
	}
	
	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f, "  as-path a%u \"^%u(.)*(%u",
			    lineNo, b->asnumber,
			    asne->asn);
		} else {
			fprintf(f,"|%u", asne->asn);
		}

		nc++;

		if (nc == b->aswidth) {
			fprintf(f, ")$\";\n");
			nc = 0;
			lineNo++;
		}
	}

	if (nc)
		fprintf(f, ")$\";\n");
	else if (lineNo == 0)
		fprintf(f, "  as-path aNone \"!.*\";\n");

	fprintf(f, " }\n}\n");
}

static void
bgpq4_print_juniper_oaspath(FILE *f, struct bgpq_expander *b)
{
	int 			 nc = 0, lineNo = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "  as-path a%u \"^%u(%u)*$\";\n", lineNo,
		    res->asn, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		lineNo++;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f,"  as-path a%u \"^(.)*(%u",
			    lineNo,
			    asne->asn);
		} else {
			fprintf(f, "|%u", asne->asn);
		}

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, ")$\";\n");
			nc = 0;
			lineNo++;
		}
	}

	if (nc)
		fprintf(f, ")$\";\n");
	else if (lineNo == 0)
		fprintf(f, " as-path aNone \"!.*\";\n");

	fprintf(f, " }\n}\n");
}

static void
bgpq4_print_juniper_aslist(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0, lineNo = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f,"policy-options {\nreplace:\n as-list-group %s {\n",
	    b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "  as-list a0 members %u;\n", res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		lineNo++;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f, "  as-list a%u members [ %u",
			    lineNo, asne->asn);
		} else {
			fprintf(f," %u", asne->asn);
		}

		nc++;

		if (nc == b->aswidth) {
			fprintf(f, " ];\n");
			nc = 0;
			lineNo++;
		}
	}

	if (nc)
		fprintf(f, " ];\n");

	fprintf(f, " }\n}\n");
}

static void
bgpq4_print_openbgpd_oaspath(FILE *f, struct bgpq_expander *b)
{
	struct asn_entry	*asne;

	if (RB_EMPTY(&b->asnlist)) {
		fprintf(f, "deny to AS %u\n", b->asnumber);
		return;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist)
		fprintf(f, "allow to AS %u AS %u\n", b->asnumber, asne->asn);
}

static void 
bgpq4_print_nokia_aspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0, lineNo = 1;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "configure router policy-options\n"
	    "begin\nno as-path-group \"%s\"\n", b->name);

	fprintf(f, "as-path-group \"%s\"\n", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "  entry 1 expression \"%u+\"\n", res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		lineNo++;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f,"  entry %u expression \"%u.*[%u",
			    lineNo, b->asnumber, asne->asn);
		} else {
			fprintf(f, " %u", asne->asn);
		}

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, "]\"\n");
			nc = 0;
			lineNo++;
		}
	}

	if (nc)
		fprintf(f, "]\"\n");

	fprintf(f,"exit\ncommit\n");
}

static void
bgpq4_print_nokia_md_aspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0, lineNo = 1;
	struct asn_entry	*asne, find, *res;

	fprintf(f,"/configure policy-options\ndelete as-path-group \"%s\"\n",
	    b->name);
	fprintf(f,"as-path-group \"%s\" {\n", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f,"  entry 1 {\n    expression \"%u+\"\n  }\n",
		    res->asn);
		lineNo++;
		RB_REMOVE(asn_tree, &b->asnlist, res);
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f,"  entry %u {\n    expression \"%u.*[%u",
			    lineNo, b->asnumber, asne->asn);
		} else {
			fprintf(f, " %u", asne->asn);
		}

		nc++;
		if (nc == b->aswidth) {
			fprintf(f,"]\"\n  }\n");
			nc = 0;
			lineNo++;
		}
	}

	if (nc)
		fprintf(f,"]\"\n  }\n");

	fprintf(f, "}\n");
}

static void
bgpq4_print_huawei_aspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "undo ip as-path-filter %s\n", b->name);

	if (RB_EMPTY(&b->asnlist)) {
		fprintf(f,"ip as-path-filter %s deny .*\n", b->name);
		return;
	}
	
	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "ip as-path-filter %s permit ^%u(_%u)*$\n",
		    b->name, res->asn, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc)
			fprintf(f, "ip as-path-filter %s permit ^%u(_[0-9]+)*"
			    "_(%u", b->name, b->asnumber, asne->asn);
		else
			fprintf(f, "|%u", asne->asn);

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, ")$\n");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f, ")$\n");
}

static void
bgpq4_print_huawei_xpl_aspath(FILE *f, struct bgpq_expander *b)
{
	int 			 nc = 0, comma = 1;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "xpl as-path-list %s", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "\n  regular ^%u(_%u)*$", res->asn, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f, "%s\n  regular ^%u(_[0-9]+)*_(%u",
			    comma ? "," : "",
			    b->asnumber,
			    asne->asn);
			comma = 1;
		} else
			fprintf(f, "|%u", asne->asn);

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, ")$");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f, ")$");

	fprintf(f, "\nend-list\n");
}

static void
bgpq4_print_huawei_oaspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f,"undo ip as-path-filter %s\n", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f,"ip as-path-filter %s permit ^(_%u)*$\n",
		    b->name, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
	}

	if (RB_EMPTY(&b->asnlist)) {
		fprintf(f, "ip as-path-filter %s deny .*\n", b->name);
		return;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f, "ip as-path-filter %s permit ^(_[0-9]+)*_(%u",
			    b->name, asne->asn);
		} else {
			fprintf(f, "|%u", asne->asn);
		}

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, ")$\n");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f, ")$\n");
}

static void
bgpq4_print_huawei_xpl_oaspath(FILE *f, struct bgpq_expander *b)
{
	int 			 nc = 0, comma = 0;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "xpl as-path-list %s", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "\n  regular ^(_%u)*$", res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		comma = 1;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f,"%s\n  regular ^(_[0-9]+)*_(%u",
			    comma ? "," : "", asne->asn);
			comma = 1;
		} else
			fprintf(f,"|%u",asne->asn);

		nc++;
		if (nc == b->aswidth) {
			fprintf(f,")$");
			nc = 0;
		}
	}

	if (nc)
		fprintf(f,")$");

	fprintf(f,"\nend-list\n");
}

static void
bgpq4_print_nokia_oaspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0, lineNo = 1;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "configure router policy-options\nbegin\nno as-path-group"
	    "\"%s\"\n", b->name);
	fprintf(f, "as-path-group \"%s\"\n", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "  entry %u expression \"%u+\"\n", lineNo,
		    b->asnumber);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		lineNo++;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f,"  entry %u expression \".*[%u",
			    lineNo, asne->asn);
		} else {
			fprintf(f," %u", asne->asn);
		}

		nc++;
		if (nc == b->aswidth) {
			fprintf(f,"]\"\n");
			nc = 0;
			lineNo++;
		}
	}

	if (nc)
		fprintf(f, "]\"\n");
}

static void
bgpq4_print_nokia_md_oaspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0, lineNo = 1;
	struct asn_entry	*asne, find, *res;

	fprintf(f, "/configure policy-options\ndelete as-path-group \"%s\"\n",
		b->name);
	fprintf(f, "as-path-group \"%s\" {\n", b->name);

	find.asn = b->asnumber;
	if ((res = RB_FIND(asn_tree, &b->asnlist, &find)) != NULL) {
		fprintf(f, "  entry %u {\n    expression \"%u+\"\n  }\n",
		    lineNo, res->asn);
		RB_REMOVE(asn_tree, &b->asnlist, res);
		lineNo++;
	}

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f,"  entry %u {\n    expression \".*[%u",
			    lineNo, asne->asn);
		} else {
			fprintf(f, " %u", asne->asn);
		}

		nc++;
		if (nc == b->aswidth) {
			fprintf(f, "]\"\n  }\n");
			nc = 0;
			lineNo++;
		}
	}

	if (nc)
		fprintf(f,"]\"\n  }\n");

	fprintf(f, "}\n");
}

static void
bgpq4_print_jprefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		return;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));
	fprintf(f,"    %s;\n", prefix);
}

static int   needscomma = 0;

static void
bgpq4_print_json_prefix(struct sx_radix_node *n, void *ff)
{
	char	prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_jsnprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "%s\n    { \"prefix\": \"%s\", \"exact\": true }",
		    needscomma ? "," : "", prefix);
	} else if (n->aggregateLow > n->prefix->masklen) {
		fprintf(f, "%s\n    { \"prefix\": \"%s\", \"exact\": false,\n"
		    "      \"greater-equal\": %u, \"less-equal\": %u }",
		    needscomma ? "," : "", prefix, n->aggregateLow,
		    n->aggregateHi);
	} else {
		fprintf(f, "%s\n    { \"prefix\": \"%s\", \"exact\": false, "
		    "\"less-equal\": %u }", needscomma ? "," : "", prefix,
		    n->aggregateHi);
	}

	needscomma = 1;

checkSon:
	if (n->son)
		bgpq4_print_json_prefix(n->son, ff);
}

static void
bgpq4_print_json_aspath(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0;
	struct asn_entry	*asne;

	fprintf(f, "{\"%s\": [", b->name);

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f, "%s\n  %u",
			    needscomma ? "," : "",
			    asne->asn);
			needscomma = 1;
		} else {
			fprintf(f, "%s%u",
			    needscomma ? "," : "",
			    asne->asn);
			needscomma = 1;
		}

		nc++;
		if (nc == b->aswidth)
			nc = 0;
	}

	fprintf(f,"\n]}\n");
}

static void
bgpq4_print_bird_prefix(struct sx_radix_node *n, void *ff)
{
	char	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "%s\n    %s", needscomma ? "," : "", prefix);
	} else if (n->aggregateLow > n->prefix->masklen) {
		fprintf(f, "%s\n    %s{%u,%u}", needscomma ? "," : "", prefix,
		    n->aggregateLow, n->aggregateHi);
	} else {
		fprintf(f, "%s\n    %s{%u,%u}", needscomma ? "," : "", prefix,
		    n->prefix->masklen, n->aggregateHi);
	}

	needscomma = 1;

checkSon:
	if (n->son)
		bgpq4_print_bird_prefix(n->son, ff);
}

static void
bgpq4_print_bird_aspath(FILE* f, struct bgpq_expander* b)
{
	int			 nc = 0;
	struct asn_entry	*asne;

	fprintf(f, "%s = [", b->name);

	if (RB_EMPTY(&b->asnlist)) {
		fprintf(f, "];\n");
		return;
	}
	
	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		if (!nc) {
			fprintf(f, "%s\n    %u", needscomma ? "," : "",
			    asne->asn);
			needscomma = 1;
		} else {
			fprintf(f, ", %u", asne->asn);
			needscomma = 1;
		}

		nc++;
		if (nc == b->aswidth)
			nc = 0;
	}

	fprintf(f, "\n];\n");
}

static void
bgpq4_print_openbgpd_prefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "\n\t%s", prefix);
	} else if (n->aggregateLow == n->aggregateHi) {
		fprintf(f, "\n\t%s prefixlen = %u", prefix, n->aggregateHi);
	} else if (n->aggregateLow > n->prefix->masklen) {
		fprintf(f, "\n\t%s prefixlen %u - %u",
		    prefix, n->aggregateLow, n->aggregateHi);
	} else {
		fprintf(f, "\n\t%s prefixlen %u - %u",
		    prefix, n->prefix->masklen, n->aggregateHi);
	}

checkSon:
	if (n->son)
		bgpq4_print_openbgpd_prefix(n->son, ff);
}

static void
bgpq4_print_openbgpd_asset(FILE *f, struct bgpq_expander *b)
{
	int			 nc = 0;
	struct asn_entry	*asne;

	fprintf(f, "as-set %s {", b->name);

	RB_FOREACH(asne, asn_tree, &b->asnlist) {
		fprintf(f, "%s%u", nc == 0 ? "\n\t" : " ", asne->asn);

		nc++;
		if (nc == b->aswidth)
			nc = 0;
		}

	fprintf(f, "\n}\n");
}

static void
bgpq4_print_openbgpd_aspath(FILE *f, struct bgpq_expander *b)
{
	struct asn_entry	*asne;

	if (RB_EMPTY(&b->asnlist)) {
		fprintf(f, "deny from AS %u\n", b->asnumber);
		return;
	}
	
	RB_FOREACH(asne, asn_tree, &b->asnlist)
		fprintf(f, "allow from AS %u AS %u\n", b->asnumber, asne->asn);
}

void
bgpq4_print_aspath(FILE *f, struct bgpq_expander *b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		bgpq4_print_juniper_aspath(f, b);
		break;
	case V_CISCO:
	case V_ARISTA:
		bgpq4_print_cisco_aspath(f, b);
		break;
	case V_CISCO_XR:
		bgpq4_print_cisco_xr_aspath(f, b);
		break;
	case V_JSON:
		bgpq4_print_json_aspath(f, b);
		break;
	case V_BIRD:
		bgpq4_print_bird_aspath(f, b);
		break;
	case V_OPENBGPD:
		bgpq4_print_openbgpd_aspath(f, b);
		break;
	case V_NOKIA:
		bgpq4_print_nokia_aspath(f, b);
		break;
	case V_NOKIA_MD:
		bgpq4_print_nokia_md_aspath(f, b);
		break;
	case V_HUAWEI:
		bgpq4_print_huawei_aspath(f, b);
		break;
	case V_HUAWEI_XPL:
		bgpq4_print_huawei_xpl_aspath(f, b);
		break;
	default:
		sx_report(SX_FATAL,"Unknown vendor %i\n", b->vendor);
	}
}

void
bgpq4_print_oaspath(FILE *f, struct bgpq_expander *b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		bgpq4_print_juniper_oaspath(f, b);
		break;
	case V_CISCO:
	case V_ARISTA:
		bgpq4_print_cisco_oaspath(f, b);
		break;
	case V_CISCO_XR:
		bgpq4_print_cisco_xr_oaspath(f, b);
		break;
	case V_OPENBGPD:
		bgpq4_print_openbgpd_oaspath(f, b);
		break;
	case V_NOKIA:
		bgpq4_print_nokia_oaspath(f, b);
		break;
	case V_NOKIA_MD:
		bgpq4_print_nokia_md_oaspath(f, b);
		break;
	case V_HUAWEI:
		bgpq4_print_huawei_oaspath(f, b);
		break;
	case V_HUAWEI_XPL:
		bgpq4_print_huawei_xpl_oaspath(f, b);
		break;
	default:
		sx_report(SX_FATAL,"Unknown vendor %i\n", b->vendor);
	}
}

void
bgpq4_print_aslist(FILE *f, struct bgpq_expander *b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		bgpq4_print_juniper_aslist(f, b);
		break;
	default:
		sx_report(SX_FATAL,"Unknown vendor %i\n", b->vendor);
	}
}

void
bgpq4_print_asset(FILE *f, struct bgpq_expander *b)
{
	switch (b->vendor) {
	case V_JSON:
		bgpq4_print_json_aspath(f, b);
		break;
	case V_OPENBGPD:
		bgpq4_print_openbgpd_asset(f, b);
		break;
	case V_BIRD:
		bgpq4_print_bird_aspath(f, b);
		break;
	default:
		sx_report(SX_FATAL, "as-sets (-t) supported for JSON, "
		    "OpenBGPD, and BIRD only\n");
	}
}

static int jrfilter_prefixed = 1;

static void
bgpq4_print_jrfilter(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "    %s%s exact;\n",
		    jrfilter_prefixed ? "route-filter " : "", prefix);
	} else {
		if (n->aggregateLow > n->prefix->masklen) {
			fprintf(f,"    %s%s prefix-length-range /%u-/%u;\n",
			    jrfilter_prefixed ? "route-filter " : "",
			    prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"    %s%s upto /%u;\n",
			    jrfilter_prefixed ? "route-filter " : "",
			    prefix, n->aggregateHi);
		}
	}

checkSon:
	if (n->son)
		bgpq4_print_jrfilter(n->son, ff);
}

static char* bname = NULL;
static int   seq = 0;

static void
bgpq4_print_cprefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128], seqno[16] = "";
	FILE	*f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (seq)
		snprintf(seqno, sizeof(seqno), " seq %i", seq++);

	if (n->isAggregate) {
		if (n->aggregateLow > n->prefix->masklen) {
			fprintf(f,"%s prefix-list %s%s permit %s ge %u le %u\n",
			    n->prefix->family == AF_INET ? "ip" : "ipv6",
			    bname ? bname : "NN", seqno, prefix,
			    n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"%s prefix-list %s%s permit %s le %u\n",
			    n->prefix->family == AF_INET ? "ip" : "ipv6",
			    bname?bname:"NN", seqno, prefix,
			    n->aggregateHi);
		}
	} else {
		fprintf(f,"%s prefix-list %s%s permit %s\n",
		    (n->prefix->family == AF_INET) ? "ip" : "ipv6",
		    bname ? bname : "NN", seqno, prefix);
	}

checkSon:
	if (n->son)
		bgpq4_print_cprefix(n->son, ff);
}

static void
bgpq4_print_cprefixxr(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (n->isAggregate) {
		if (n->aggregateLow > n->prefix->masklen) {
			fprintf(f,"%s%s ge %u le %u",
			    needscomma ? ",\n " : " ",
			    prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"%s%s le %u",
			    needscomma ? ",\n " : " ",
			    prefix, n->aggregateHi);
		}
	} else {
		fprintf(f, "%s%s",
		    needscomma ? ",\n " : " ",
		    prefix);
	}

	needscomma = 1;

checkSon:
	if (n->son)
		bgpq4_print_cprefixxr(n->son, ff);
}

static void
bgpq4_print_hprefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf_sep(n->prefix, prefix, sizeof(prefix), " ");

	if (n->isAggregate) {
		if (n->aggregateLow > n->prefix->masklen) {
			fprintf(f,"ip %s-prefix %s permit %s greater-equal %u "
			    "less-equal %u\n",
			    n->prefix->family == AF_INET ? "ip" : "ipv6",
			    bname ? bname : "NN",
			    prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"ip %s-prefix %s permit %s less-equal %u\n",
			    n->prefix->family == AF_INET ? "ip" : "ipv6",
			    bname ? bname : "NN",
			    prefix, n->aggregateHi);
		}
	} else {
		fprintf(f,"ip %s-prefix %s permit %s\n",
		    n->prefix->family == AF_INET ? "ip" : "ipv6",
		    bname ? bname : "NN",
		    prefix);
	}

checkSon:
	if (n->son)
		bgpq4_print_hprefix(n->son, ff);
}

static void
bgpq4_print_hprefixxpl(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf_sep(n->prefix, prefix, sizeof(prefix), " ");

	if (n->isAggregate) {
		if (n->aggregateLow>n->prefix->masklen) {
			fprintf(f,"%s %s ge %u le %u",
			    needscomma ? ",\n " : " ",
			    prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"%s %s le %u",
			    needscomma ? ",\n " : " ",
			    prefix, n->aggregateHi);
		}
	} else {
		fprintf(f, "%s %s",
		    needscomma ? ",\n " : " ",
		    prefix);
	}

	needscomma = 1;

checkSon:
	if (n->son)
		bgpq4_print_hprefixxpl(n->son, ff);
}

static void
bgpq4_print_eprefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128], seqno[16] = "";
	FILE	*f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	snprintf(seqno, sizeof(seqno), " seq %i", seq++);

	if (n->isAggregate) {
		if (n->aggregateLow > n->prefix->masklen) {
			fprintf(f,"   %s permit %s ge %u le %u\n",
			    seqno, prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"   %s permit %s le %u\n",
			    seqno, prefix, n->aggregateHi);
		}
	} else {
		fprintf(f,"   %s permit %s\n", seqno, prefix);
	}

checkSon:
	if (n->son)
		bgpq4_print_eprefix(n->son, ff);
}

static void
bgpq4_print_ceacl(struct sx_radix_node *n, void *ff)
{
	char 	 	 prefix[128];
	FILE		*f = (FILE*)ff;
	char		*c;
	struct in_addr	 netmask;
	
	netmask.s_addr = 0xfffffffful;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	c = strchr(prefix, '/');

	if (c)
		*c = 0;

	if (n->prefix->masklen == 32)
		netmask.s_addr = 0;
	else {
	 	netmask.s_addr <<= (32 - n->prefix->masklen);
		netmask.s_addr &= 0xfffffffful;
	}

	netmask.s_addr = htonl(netmask.s_addr);

	if (n->isAggregate) {
		struct in_addr	mask, wildaddr, wild2addr, wildmask;
		int		masklen = n->aggregateLow;

		mask.s_addr = 0xfffffffful;
		wildaddr.s_addr = 0xfffffffful >> n->prefix->masklen;

		if (n->aggregateHi == 32)
			wild2addr.s_addr = 0;
		else
			wild2addr.s_addr = 0xfffffffful >> n->aggregateHi;

		wildaddr.s_addr = wildaddr.s_addr & (~wild2addr.s_addr);

		if (masklen == 32)
			mask.s_addr = 0xfffffffful;
		else
			mask.s_addr = 0xfffffffful & (0xfffffffful << (32 - masklen));

		if (n->aggregateHi == 32)
			wild2addr.s_addr = 0;
		else
			wild2addr.s_addr = 0xfffffffful >> n->aggregateHi;

		wildmask.s_addr = (0xfffffffful >> n->aggregateLow)
		    & (~wild2addr.s_addr);

		mask.s_addr = htonl(mask.s_addr);
		wildaddr.s_addr = htonl(wildaddr.s_addr);
		wildmask.s_addr = htonl(wildmask.s_addr);

		if (wildaddr.s_addr) {
			fprintf(f, " permit ip %s ",
			    inet_ntoa(n->prefix->addr.addr));
			fprintf(f, "%s ", inet_ntoa(wildaddr));
		} else {
			fprintf(f, " permit ip host %s ",
			    inet_ntoa(n->prefix->addr.addr));
		}

		if (wildmask.s_addr) {
			fprintf(f, "%s ", inet_ntoa(mask));
			fprintf(f, "%s\n", inet_ntoa(wildmask));
		} else {
			fprintf(f, "host %s\n", inet_ntoa(mask));
		}
	} else {
		fprintf(f, " permit ip host %s host %s\n", prefix,
		    inet_ntoa(netmask));
	}

checkSon:
	if (n->son)
		bgpq4_print_ceacl(n->son, ff);
}

static void
bgpq4_print_nokia_ipfilter(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	fprintf(f, "    prefix %s\n", prefix);

checkSon:
	if (n->son)
		bgpq4_print_nokia_ipfilter(n->son, ff);
}

static void
bgpq4_print_nokia_md_ipfilter(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	fprintf(f, "    prefix %s { }\n", prefix);

checkSon:
	if (n->son)
		bgpq4_print_nokia_md_ipfilter(n->son, ff);
}

static void
bgpq4_print_nokia_prefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "    prefix %s exact\n", prefix);
	} else {
		if (n->aggregateLow > n->prefix->masklen) {
			fprintf(f,"    prefix %s prefix-length-range %u-%u\n",
			    prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"    prefix %s prefix-length-range %u-%u\n",
			    prefix, n->prefix->masklen, n->aggregateHi);
		}
	}

checkSon:
	if (n->son)
		bgpq4_print_nokia_prefix(n->son, ff);

}

static void
bgpq4_print_nokia_md_prefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "    prefix %s type exact {\n    }\n", prefix);
	} else {
		if (n->aggregateLow > n->prefix->masklen) {
			fprintf(f,"    prefix %s type range {\n"
			    "        start-length %u\n"
			    "        end-length %u\n    }\n",
			    prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"    prefix %s type through {\n        "
			    "through-length %u\n    }\n", prefix,
			    n->aggregateHi);
		}
	}

checkSon:
	if (n->son)
		bgpq4_print_nokia_md_prefix(n->son, ff);

}

static void
bgpq4_print_nokia_srl_prefix(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "    prefix %s mask-length-range exact { }\n", prefix);
	} else {
		fprintf(f, "    prefix %s mask-length-range %u..%u { }\n", prefix, 
		  max(n->aggregateLow,n->prefix->masklen), n->aggregateHi);
	}

checkSon:
	if (n->son)
		bgpq4_print_nokia_srl_prefix(n->son, ff);
}

typedef struct {
	FILE *f;
	int seq;
} NOKIA_SRL_IPFILTER_PARAMS;

static void
bgpq4_print_nokia_srl_ipfilter(struct sx_radix_node *n, void *ff)
{
	char 	 prefix[128];
	NOKIA_SRL_IPFILTER_PARAMS *params = (NOKIA_SRL_IPFILTER_PARAMS*) ff;

	if (n->isGlue)
		goto checkSon;

	if (!params->f)
		params->f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	fprintf(params->f, " entry %d {\n  action { accept { } }\n  match { source-ip { prefix %s } } }\n", params->seq, prefix);
	params->seq += 10;

checkSon:
	if (n->son) {
		bgpq4_print_nokia_srl_ipfilter(n->son, ff);
	}
}

static void
bgpq4_print_juniper_prefixlist(FILE *f, struct bgpq_expander *b)
{
	fprintf(f, "policy-options {\nreplace:\n prefix-list %s {\n",
	    b->name ? b->name : "NN");

	sx_radix_tree_foreach(b->tree, bgpq4_print_jprefix, f);

	fprintf(f, " }\n}\n");
}

static void
bgpq4_print_juniper_routefilter(FILE *f, struct bgpq_expander *b)
{
	char	*c = NULL;

	if (b->name && (c = strchr(b->name,'/'))) {
		*c = 0;
		fprintf(f, "policy-options {\n policy-statement %s {\n"
		    "  term %s {\n"
		    "replace:\n   from {\n",
		    b->name, c + 1);
		if (b->match)
			fprintf(f, "    %s;\n", b->match);
	} else {
		fprintf(f, "policy-options {\n policy-statement %s { \n"
		    "replace:\n  from {\n", b->name ? b->name : "NN");
		if (b->match)
			fprintf(f, "    %s;\n", b->match);
	}

	if (!sx_radix_tree_empty(b->tree)) {
		jrfilter_prefixed = 1;
		sx_radix_tree_foreach(b->tree, bgpq4_print_jrfilter, f);
	} else {
		fprintf(f, "    route-filter %s/0 orlonger reject;\n",
			b->tree->family == AF_INET ? "0.0.0.0" : "::");
	}

	if (c) {
		fprintf(f, "   }\n  }\n }\n}\n");
	} else {
		fprintf(f, "  }\n }\n}\n");
	}
}

static void
bgpq4_print_openbgpd_prefixlist(FILE *f, struct bgpq_expander *b)
{
	if (sx_radix_tree_empty(b->tree)) {
		fprintf(f, "# generated prefix-list %s (AS %u) is empty\n",
		    b->name, b->asnumber);
		if (!b->asnumber)
			fprintf(f, "# use -a <asn> to generate \"deny from "
			    "ASN <asn>\" instead of this list\n");
	}

	if (!sx_radix_tree_empty(b->tree) || !b->asnumber) {
		if (b->name) {
			if (strcmp(b->name, "NN") != 0) {
				fprintf(f, "%s=\"", b->name);
			}
		}
		fprintf(f, "prefix { ");
		sx_radix_tree_foreach(b->tree, bgpq4_print_openbgpd_prefix, f);
		fprintf(f, "\n\t}");
		if (b->name) {
			if (strcmp(b->name, "NN") != 0) {
				fprintf(f, "\"");
			}
		}
		fprintf(f, "\n");
	} else {
		fprintf(f, "deny from AS %u\n", b->asnumber);
	}
}

static void
bgpq4_print_openbgpd_prefixset(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "prefix-set %s {", bname);

	if (!sx_radix_tree_empty(b->tree))
		sx_radix_tree_foreach(b->tree, bgpq4_print_openbgpd_prefix, f);

	fprintf(f, "\n}\n");
}

static void
bgpq4_print_cisco_prefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";
	seq = b->sequence;

	fprintf(f, "no %s prefix-list %s\n",
	    b->family == AF_INET ? "ip" : "ipv6",
	    bname);

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_cprefix, f);
	} else {
		fprintf(f, "! generated prefix-list %s is empty\n", bname);
		fprintf(f, "%s prefix-list %s%s deny %s\n",
		    (b->family == AF_INET) ? "ip" : "ipv6",
		    bname,
		    seq ? " seq 1" : "",
		    (b->family == AF_INET) ? "0.0.0.0/0" : "::/0");
	}
}

static void
bgpq4_print_ciscoxr_prefixlist(FILE *f, struct bgpq_expander *b)
{
	fprintf(f, "no prefix-set %s\n", b->name);
	fprintf(f, "prefix-set %s\n", b->name);

	sx_radix_tree_foreach(b->tree, bgpq4_print_cprefixxr, f);

	fprintf(f, "\nend-set\n");
}

static void
bgpq4_print_json_prefixlist(FILE *f, struct bgpq_expander *b)
{
	fprintf(f, "{ \"%s\": [", b->name);

	sx_radix_tree_foreach(b->tree, bgpq4_print_json_prefix, f);

	fprintf(f,"\n] }\n");
}

static void
bgpq4_print_bird_prefixlist(FILE *f, struct bgpq_expander *b)
{
	if (!sx_radix_tree_empty(b->tree)) {
		fprintf(f,"%s = [",
		    b->name ? b->name : "NN");
		sx_radix_tree_foreach(b->tree, bgpq4_print_bird_prefix, f);
		fprintf(f, "\n];\n");
	} else {
		SX_DEBUG(debug_expander, "skip empty prefix-list in BIRD format\n");
	}
}

static void
bgpq4_print_huawei_prefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";
	seq = b->sequence;

	fprintf(f,"undo ip %s-prefix %s\n",
		(b->family == AF_INET) ? "ip" : "ipv6", bname);

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_hprefix, f);
	} else {
		fprintf(f, "ip %s-prefix %s%s deny %s\n",
		    (b->family == AF_INET) ? "ip" : "ipv6",
		    bname,
		    seq ? " seq 1" : "",
		    (b->family == AF_INET) ? "0.0.0.0/0" : "::/0");
	}
}

static void
bgpq4_print_huawei_xpl_prefixlist(FILE* f, struct bgpq_expander* b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "no xpl %s-prefix-list %s\nxpl %s-prefix-list %s\n", b->family==AF_INET ? "ip" : "ipv6", bname, b->family==AF_INET ? "ip" : "ipv6", bname);

	sx_radix_tree_foreach(b->tree, bgpq4_print_hprefixxpl, f);

	fprintf(f, "\nend-list\n");
}

static void
bgpq4_print_arista_prefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";
	seq = b->sequence;

	fprintf(f, "no %s prefix-list %s\n",
	    b->family == AF_INET ? "ip" : "ipv6",
	    bname);

	if (!sx_radix_tree_empty(b->tree)) {
		fprintf(f,"%s prefix-list %s\n",
		    b->family == AF_INET ? "ip" : "ipv6",
		    bname);

		sx_radix_tree_foreach(b->tree, bgpq4_print_eprefix, f);
	} else {
		fprintf(f, "! generated prefix-list %s is empty\n", bname);
		fprintf(f, "%s prefix-list %s\n   seq %i deny %s\n",
		    (b->family == AF_INET) ? "ip" : "ipv6",
		    bname,
		    seq,
		    (b->family == AF_INET) ? "0.0.0.0/0" : "::/0");
	}
}

struct fpcbdata {
	FILE			*f;
	struct bgpq_expander	*b;
};

static void
bgpq4_print_format_prefix(struct sx_radix_node *n, void *ff)
{
	struct fpcbdata		*fpc = (struct fpcbdata*)ff;
	FILE			*f = fpc->f;
	struct bgpq_expander	*b = fpc->b;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	if (!n->isAggregate) {
		sx_prefix_snprintf_fmt(n->prefix, f,
		    b->name ? b->name : "NN",
		    b->format,
		    n->prefix->masklen,
		    n->prefix->masklen);
	} else if (n->aggregateLow > n->prefix->masklen) {
		sx_prefix_snprintf_fmt(n->prefix, f,
		    b->name ? b->name : "NN",
		    b->format,
		    n->aggregateLow,
		    n->aggregateHi);
	} else {
		sx_prefix_snprintf_fmt(n->prefix, f,
		    b->name ? b->name : "NN",
		    b->format,
		    n->prefix->masklen,
		    n->aggregateHi);
	}

checkSon:
	if (n->son)
		bgpq4_print_format_prefix(n->son, ff);
}

static void
bgpq4_print_format_prefixlist(FILE *f, struct bgpq_expander *b)
{
	struct fpcbdata ff = {.f=f, .b=b};
	int len = strlen(b->format);

	sx_radix_tree_foreach(b->tree, bgpq4_print_format_prefix, &ff);

	// Add newline if format doesn't already end with one.
	if (len < 2 ||
	    !(b->format[len-2] == '\\' && b->format[len-1] == 'n'))
		fprintf(f, "\n");
}

static void
bgpq4_print_nokia_prefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";
	fprintf(f,"configure router policy-options\nbegin\nno prefix-list \"%s\"\n",
		bname);
	fprintf(f,"prefix-list \"%s\"\n", bname);
	sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_prefix, f);
	fprintf(f,"exit\ncommit\n");
}

static void
bgpq4_print_cisco_eacl(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f,"no ip access-list extended %s\n", bname);

	if (!sx_radix_tree_empty(b->tree)) {
		fprintf(f, "ip access-list extended %s\n", bname);
		sx_radix_tree_foreach(b->tree, bgpq4_print_ceacl, f);
	} else {
		fprintf(f, "! generated access-list %s is empty\n", bname);
		fprintf(f, "ip access-list extended %s deny any any\n", bname);
	}
}

static void
bgpq4_print_nokia_ipprefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "configure filter match-list\nno %s-prefix-list \"%s\"\n",
	    (b->tree->family == AF_INET) ? "ip" : "ipv6", bname);

	fprintf(f, "%s-prefix-list \"%s\" create\n",
	    b->tree->family == AF_INET ? "ip":"ipv6", bname);

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_ipfilter, f);
	} else {
		fprintf(f, "# generated ip-prefix-list %s is empty\n", bname);
	}

	fprintf(f,"exit\n");
}

static void
bgpq4_print_nokia_md_prefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f,"/configure filter match-list\ndelete %s-prefix-list \"%s\"\n",
	    b->tree->family == AF_INET ? "ip" : "ipv6", bname);

	fprintf(f,"%s-prefix-list \"%s\" {\n",
	    b->tree->family == AF_INET ? "ip" : "ipv6", bname);

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_md_ipfilter, f);
	} else {
		fprintf(f,"# generated %s-prefix-list %s is empty\n",
		    b->tree->family == AF_INET ? "ip" : "ipv6", bname);
	}

	fprintf(f,"}\n");
}

static void
bgpq4_print_nokia_md_ipprefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "/configure policy-options\ndelete prefix-list \"%s\"\n",
	    bname);

	fprintf(f, "prefix-list \"%s\" {\n", bname);

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_md_prefix, f);
	}

	fprintf(f,"}\n");
}

static void
bgpq4_print_nokia_srl_prefixset(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "/routing-policy\ndelete prefix-set \"%s\"\n",
	    bname);

	fprintf(f, "prefix-set \"%s\" {\n", bname);

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_srl_prefix, f);
	}

	fprintf(f,"}\n");
}

static void
bgpq4_print_nokia_srl_aclipfilter(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f,"/acl \ndelete ipv%c-filter \"%s\"\n",
	    b->tree->family == AF_INET ? '4' : '6', bname);

	fprintf(f,"ipv%c-filter \"%s\" {\n",
	    b->tree->family == AF_INET ? '4' : '6', bname);

	if (!sx_radix_tree_empty(b->tree)) {
		NOKIA_SRL_IPFILTER_PARAMS params = { f, 10 };
		sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_srl_ipfilter, &params);
	} else {
		fprintf(f,"# generated ipv%c-filter '%s' is empty\n",
		    b->tree->family == AF_INET ? '4' : '6', bname);
	}

	fprintf(f,"}\n");
}

static void
bgpq4_print_k6prefix(struct sx_radix_node *n, void *ff)
{
	char	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf_sep(n->prefix, prefix, sizeof(prefix), "/");

	if (n->isAggregate)
		fprintf(f,"/routing filter add action=accept chain=\""
		    "%s-%s\" prefix=%s prefix-length=%d-%d\n",
		    bname ? bname : "NN",
		    n->prefix->family == AF_INET ? "V4" : "V6",
		    prefix, n->aggregateLow, n->aggregateHi);
	else
		fprintf(f,"/routing filter add action=accept chain=\""
		    "%s-%s\" prefix=%s\n",
		    bname ? bname : "NN",
		    n->prefix->family == AF_INET ? "V4" : "V6",
		    prefix);

checkSon:
	if (n->son)
		bgpq4_print_k6prefix(n->son, ff);
}

static void
bgpq4_print_k7prefix(struct sx_radix_node *n, void *ff)
{
	char	 prefix[128];
	FILE	*f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf_sep(n->prefix, prefix, sizeof(prefix), "/");

	if (n->isAggregate)
		fprintf(f,"/routing filter rule add chain=\""
		    "%s-%s\"  rule=\"if (dst in %s && dst-len in %d-%d) {accept}\"\n",
		    bname ? bname : "NN",
		    n->prefix->family == AF_INET ? "V4" : "V6",
		    prefix, n->aggregateLow, n->aggregateHi);
	else
		fprintf(f,"/routing filter rule add chain=\""
		    "%s-%s\" rule=\"if (dst==%s) {accept}\"\n",
		    bname ? bname : "NN",
		    n->prefix->family == AF_INET ? "V4" : "V6",
		    prefix);

checkSon:
	if (n->son)
		bgpq4_print_k7prefix(n->son, ff);
}

static void
bgpq4_print_mikrotik_prefixlist(FILE *f, struct bgpq_expander *b)
{
	bname = b->name ? b->name : "NN";
	void *cbfunc = bgpq4_print_k6prefix;

	if (b->vendor == V_MIKROTIK7)
		cbfunc = bgpq4_print_k7prefix;

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, cbfunc, f);
	} else {
		fprintf(f, "# generated prefix-list %s is empty\n", bname);
	}
}

void
bgpq4_print_prefixlist(FILE *f, struct bgpq_expander *b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		bgpq4_print_juniper_prefixlist(f, b);
		break;
	case V_CISCO:
		bgpq4_print_cisco_prefixlist(f, b);
		break;
	case V_CISCO_XR:
		bgpq4_print_ciscoxr_prefixlist(f, b);
		break;
	case V_JSON:
		bgpq4_print_json_prefixlist(f, b);
		break;
	case V_BIRD:
		bgpq4_print_bird_prefixlist(f, b);
		break;
	case V_OPENBGPD:
		bgpq4_print_openbgpd_prefixlist(f, b);
		break;
	case V_FORMAT:
		bgpq4_print_format_prefixlist(f, b);
		break;
	case V_NOKIA:
		bgpq4_print_nokia_prefixlist(f, b);
		break;
	case V_NOKIA_MD:
		bgpq4_print_nokia_md_ipprefixlist(f, b);
		break;
	case V_NOKIA_SRL:
		bgpq4_print_nokia_srl_prefixset(f, b);
		break;
	case V_HUAWEI:
		bgpq4_print_huawei_prefixlist(f, b);
		break;
	case V_HUAWEI_XPL:
		bgpq4_print_huawei_xpl_prefixlist(f, b);
		break;
	case V_MIKROTIK6:
	case V_MIKROTIK7:
		bgpq4_print_mikrotik_prefixlist(f, b);
		break;
	case V_ARISTA:
		bgpq4_print_arista_prefixlist(f, b);
		break;
	}
}

void
bgpq4_print_eacl(FILE *f, struct bgpq_expander *b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		bgpq4_print_juniper_routefilter(f, b);
		break;
	case V_CISCO:
	case V_ARISTA:
		bgpq4_print_cisco_eacl(f, b);
		break;
	case V_OPENBGPD:
		bgpq4_print_openbgpd_prefixset(f, b);
		break;
	case V_NOKIA:
		bgpq4_print_nokia_ipprefixlist(f, b);
		break;
	case V_NOKIA_MD:
		bgpq4_print_nokia_md_prefixlist(f, b);
		break;
	case V_NOKIA_SRL:
		bgpq4_print_nokia_srl_aclipfilter(f, b);
		break;
	default:
		sx_report(SX_FATAL, "unreachable point\n");
	}
}

static void
bgpq4_print_juniper_route_filter_list(FILE *f, struct bgpq_expander *b)
{
	fprintf(f, "policy-options {\nreplace:\n  route-filter-list %s {\n",
	    b->name ? b->name : "NN");

	if (sx_radix_tree_empty(b->tree)) {
		fprintf(f, "    %s/0 orlonger reject;\n",
		    b->tree->family == AF_INET ? "0.0.0.0" : "::");
	} else {
		jrfilter_prefixed = 0;
		sx_radix_tree_foreach(b->tree, bgpq4_print_jrfilter, f);
	}

	fprintf(f, "  }\n}\n");
}

void
bgpq4_print_route_filter_list(FILE *f, struct bgpq_expander *b)
{
	switch(b->vendor) {
	case V_JUNIPER:
		bgpq4_print_juniper_route_filter_list(f, b);
		break;
	default:
		sx_report(SX_FATAL, "unreachable point\n");
	}
}
