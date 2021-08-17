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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "bgpq4.h"
#include "sx_report.h"

extern int debug_expander;

int bgpq4_print_json_aspath(FILE* f, struct bgpq_expander* b);
int bgpq4_print_bird_aspath(FILE* f, struct bgpq_expander* b);
int bgpq4_print_openbgpd_aspath(FILE* f, struct bgpq_expander* b);
int bgpq4_print_openbgpd_asset(FILE* f, struct bgpq_expander* b);

int
bgpq4_print_cisco_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k, empty = 1;

	fprintf(f, "no ip as-path access-list %s\n", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65536][(b->asnumber % 65536) / 8] &
	    (0x80 >> (b->asnumber % 8))) {
		fprintf(f,"ip as-path access-list %s permit ^%u(_%u)*$\n",
		    b->name ? b->name: "NN", b->asnumber, b->asnumber);
		empty = 0;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j <8;j++) {
				if (b->asn32s[k][i] & (0x80>>j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f, "ip as-path access-list %s permit"
						    " ^%u(_[0-9]+)*_(%u",
						    b->name ? b->name : "NN",
						    b->asnumber, k * 65536 + i * 8 + j);
						empty = 0;
					} else {
						fprintf(f,"|%u", k * 65536 + i * 8 + j);
						empty = 0;
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f, ")$\n");
						nc = 0;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f,")$\n");

	if (empty)
		fprintf(f, "ip as-path access-list %s deny .*\n",
		    b->name ? b->name : "NN");

	return 0;
}

int
bgpq4_print_cisco_xr_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k, comma = 0;

	fprintf(f, "as-path-set %s", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65536][(b->asnumber % 65536) / 8] &
	    (0x80 >> (b->asnumber%8))) {
		fprintf(f,"\n  ios-regex '^%u(_%u)*$'", b->asnumber,
		    b->asnumber);
		comma = 1;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f, "%s\n  ios-regex '^%u(_[0-9]+)*_(%u",
						    comma ? "," : "",
						    b->asnumber,
						    k * 65536 + i * 8 + j);
						comma = 1;
					} else {
						fprintf(f, "|%u",
						    k * 65536 + i * 8 + j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f, ")$'");
						nc = 0;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, ")$'");

	fprintf(f, "\nend-set\n");
	return 0;
}

int
bgpq4_print_cisco_oaspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k, empty = 1;

	fprintf(f, "no ip as-path access-list %s\n", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65536][(b->asnumber % 65536) / 8] &
	    (0x80 >> (b->asnumber % 8))) {
		fprintf(f,"ip as-path access-list %s permit ^(_%u)*$\n",
		    b->name ? b->name : "NN",
		    b->asnumber);
		empty = 0;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f,"ip as-path access-list %s permit"
						    " ^(_[0-9]+)*_(%u",
						    b->name ? b->name : "NN",
						    k * 65536 + i * 8 + j);
						empty = 0;
					} else {
						fprintf(f,"|%u",k*65536+i*8+j);
						empty = 0;
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f,")$\n");
						nc = 0;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, ")$\n");

	if (empty)
		fprintf(f,"ip as-path access-list %s deny .*\n",
		    b->name ? b->name : "NN");

	return 0;
}

int
bgpq4_print_cisco_xr_oaspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k, comma = 0;

	fprintf(f, "as-path-set %s", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65536][(b->asnumber % 65536) / 8] &
	    (0x80 >> (b->asnumber % 8))) {
		fprintf(f,"\n  ios-regex '^(_%u)*$'", b->asnumber);
		comma = 1;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {

				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f,"%s\n  ios-regex '^(_[0-9]+)*_(%u",
						    comma ? "," : "",
						    k * 65536 + i * 8 + j);
						comma = 1;
					} else {
						fprintf(f,"|%u",k*65536+i*8+j);
					}

					nc++;
					if (nc == b->aswidth) {
						fprintf(f,")$'");
						nc = 0;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f,")$'");

	fprintf(f,"\nend-set\n");

	return 0;
}

int
bgpq4_print_juniper_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, lineNo = 0, i, j, k;

	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n",
	    b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65535][(b->asnumber % 65536) / 8]
	    & (0x80 >> (b->asnumber % 8))) {
		fprintf(f,"  as-path a%u \"^%u(%u)*$\";\n", lineNo,
		    b->asnumber, b->asnumber);
		lineNo++;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f, "  as-path a%u \"^%u(.)*(%u",
						    lineNo, b->asnumber,
						    k * 65536 + i * 8 + j);
					} else {
						fprintf(f,"|%u",
						    k * 65536 + i * 8 + j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f, ")$\";\n");
						nc = 0;
						lineNo++;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, ")$\";\n");
	else if (lineNo == 0)
		fprintf(f, "  as-path aNone \"!.*\";\n");

	fprintf(f, " }\n}\n");

	return 0;
}

int
bgpq4_print_juniper_oaspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, lineNo = 0, i, j, k;

	fprintf(f,"policy-options {\nreplace:\n as-path-group %s {\n",
	    b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65536][(b->asnumber % 65536) / 8]
	    & (0x80 >> (b->asnumber % 8))) {
		fprintf(f, "  as-path a%u \"^%u(%u)*$\";\n", lineNo,
		    b->asnumber, b->asnumber);
		lineNo++;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f,"  as-path a%u \"^(.)*(%u",
						    lineNo,
						    k * 65536 + i * 8 + j);
					} else {
						fprintf(f, "|%u",
						    k * 65536 + i* 8 + j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f, ")$\";\n");
						nc = 0;
						lineNo++;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, ")$\";\n");
	else if (lineNo == 0)
		fprintf(f, " as-path aNone \"!.*\";\n");

	fprintf(f, " }\n}\n");

	return 0;
}

int
bgpq4_print_openbgpd_oaspath(FILE* f, struct bgpq_expander* b)
{
	int i, j, k, lineNo = 0;

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0 ; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {
					fprintf(f, "allow to AS %u AS %u\n",
					    b->asnumber,
					    k * 65536 + i * 8 + j);
					lineNo++;
				}
			}
		}
	}

	if (!lineNo)
		fprintf(f, "deny to AS %u\n", b->asnumber);

	return 0;
}

int
bgpq4_print_nokia_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, lineNo = 1, i, j, k;

	fprintf(f, "configure router policy-options\n"
	    "begin\nno as-path-group \"%s\"\n",
	    b->name ? b->name : "NN");

	fprintf(f, "as-path-group \"%s\"\n", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65535][(b->asnumber % 65536) / 8] &
	    (0x80 >> (b->asnumber % 8))) {
		fprintf(f, "  entry %u expression \"%u+\"\n", lineNo,
		    b->asnumber);
		lineNo++;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f,"  entry %u expression \"%u.*[%u",
						    lineNo, b->asnumber,
						    k * 65536 + i * 8 + j);
					} else {
						fprintf(f, " %u",
						    k * 65536 + i * 8 + j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f, "]\"\n");
						nc = 0;
						lineNo++;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, "]\"\n");

	fprintf(f,"exit\ncommit\n");

	return 0;
}

int
bgpq4_print_nokia_md_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, lineNo = 1, i, j, k;

	fprintf(f,"/configure policy-options\ndelete as-path-group \"%s\"\n",
	    b->name ? b->name : "NN");
	fprintf(f,"as-path-group \"%s\" {\n", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65535][(b->asnumber % 65536) / 8] &
	    (0x80 >> (b->asnumber % 8))) {
		fprintf(f,"  entry %u {\n    expression \"%u+\"\n  }\n",
		    lineNo, b->asnumber);
		lineNo++;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {

				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f,"  entry %u {\n    expression \"%u.*[%u",
						    lineNo, b->asnumber,
						    k * 65536 + i * 8 + j);
					} else {
						fprintf(f, " %u",
						    k * 65536 + i * 8 + j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f,"]\"\n  }\n");
						nc = 0;
						lineNo++;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f,"]\"\n  }\n");

	fprintf(f, "}\n");

	return 0;
}


int
bgpq4_print_huawei_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k, empty = 1;

	fprintf(f, "undo ip as-path-filter %s\n",
		b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65535][(b->asnumber % 65536) / 8] &
	    (0x80 >> (b->asnumber % 8))) {
		fprintf(f, "ip as-path-filter %s permit ^%u(_%u)*$\n",
		    b->name ? b->name : "NN", b->asnumber, b->asnumber);
		empty = 0;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8 ; j++) {

				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f, "ip as-path-filter %s permit ^%u(_[0-9]+)*"
						    "_(%u",
						    b->name ? b->name : "NN",
						    b->asnumber,
						    k * 65536 + i * 8 + j);
						empty = 0;
					} else {
						fprintf(f, "|%u",
						    k * 65536 + i * 8 + j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f, ")$\n");
						nc = 0;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, ")$\n");

	if (empty)
		fprintf(f,"ip as-path-filter %s deny .*\n",
		    b->name ? b->name : "NN");

	return 0;
}

int
bgpq4_print_huawei_oaspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k, empty = 1;

	fprintf(f,"undo ip as-path-filter %s\n",
	    b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	     b->asn32s[b->asnumber / 65536][(b->asnumber % 65536) / 8] &
	     (0x80 >> (b->asnumber % 8))) {
		fprintf(f,"ip as-path-filter %s permit ^(_%u)*$\n",
		    b->name ? b->name : "NN", b->asnumber);
		empty = 0;
	}

	for ( k = 0 ; k < 65536 ; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0 ; i < 8192 ; i++) {
			for (j = 0 ; j < 8 ; j++) {

				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f, "ip as-path-filter %s permit ^(_[0-9]+)*_(%u",
							b->name?b->name:"NN",k*65536+i*8+j);
					} else {
						fprintf(f, "|%u",k*65536+i*8+j);
					}

					nc++;
					empty = 0;

					if (nc == b->aswidth) {
						fprintf(f, ")$\n");
						nc = 0;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, ")$\n");

	if (empty)
		fprintf(f, "ip as-path-filter %s deny .*\n",
		    b->name ? b->name : "NN");

	return 0;
}

int
bgpq4_print_nokia_oaspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, lineNo = 1, i, j, k;

	fprintf(f, "configure router policy-options\nbegin\nno as-path-group"
	    "\"%s\"\n", b->name ? b->name : "NN");
	fprintf(f,"as-path-group \"%s\"\n", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber/65536][(b->asnumber%65536)/8] &
	    (0x80 >> (b->asnumber % 8))) {
		fprintf(f, "  entry %u expression \"%u+\"\n", lineNo,
		    b->asnumber);
		lineNo++;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f,"  entry %u expression \".*[%u",
						    lineNo,
						    k * 65536 + i * 8 + j);
					} else {
						fprintf(f," %u",k*65536+i*8+j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f,"]\"\n");
						nc = 0;
						lineNo++;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f, "]\"\n");

	return 0;
}

int
bgpq4_print_nokia_md_oaspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, lineNo = 1, i, j, k;

	fprintf(f, "/configure policy-options\ndelete as-path-group \"%s\"\n",
		b->name ? b->name : "NN");
	fprintf(f, "as-path-group \"%s\" {\n", b->name ? b->name : "NN");

	if (b->asn32s[b->asnumber / 65536] &&
	    b->asn32s[b->asnumber / 65536][(b->asnumber % 65536) / 8] &
	    (0x80>>(b->asnumber%8))) {
		fprintf(f, "  entry %u {\n    expression \"%u+\"\n  }\n",
		    lineNo, b->asnumber);
		lineNo++;
	}

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (k * 65536 + i * 8 + j == b->asnumber)
						continue;

					if (!nc) {
						fprintf(f,"  entry %u {\n    expression \".*[%u",
						    lineNo,
						    k * 65536 + i * 8 + j);
					} else {
						fprintf(f, " %u",
						    k * 65536 + i * 8 + j);
					}

					nc++;

					if (nc == b->aswidth) {
						fprintf(f, "]\"\n  }\n");
						nc = 0;
						lineNo++;
					}
				}
			}
		}
	}

	if (nc)
		fprintf(f,"]\"\n  }\n");

	fprintf(f, "}\n");

	return 0;
}

int
bgpq4_print_aspath(FILE* f, struct bgpq_expander* b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		return bgpq4_print_juniper_aspath(f, b);
	case V_CISCO:
		return bgpq4_print_cisco_aspath(f, b);
	case V_CISCO_XR:
		return bgpq4_print_cisco_xr_aspath(f, b);
	case V_JSON:
		return bgpq4_print_json_aspath(f, b);
	case V_BIRD:
		return bgpq4_print_bird_aspath(f, b);
	case V_OPENBGPD:
		return bgpq4_print_openbgpd_aspath(f, b);
	case V_NOKIA:
		return bgpq4_print_nokia_aspath(f, b);
	case V_NOKIA_MD:
		return bgpq4_print_nokia_md_aspath(f, b);
	case V_HUAWEI:
		return bgpq4_print_huawei_aspath(f, b);
	case V_ARISTA:
		return bgpq4_print_cisco_aspath(f, b);
	default:
		sx_report(SX_FATAL,"Unknown vendor %i\n", b->vendor);
	}

	return 0;
}

int
bgpq4_print_oaspath(FILE* f, struct bgpq_expander* b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		return bgpq4_print_juniper_oaspath(f, b);
	case V_CISCO:
		return bgpq4_print_cisco_oaspath(f, b);
	case V_CISCO_XR:
		return bgpq4_print_cisco_xr_oaspath(f, b);
	case V_OPENBGPD:
		return bgpq4_print_openbgpd_oaspath(f, b);
	case V_NOKIA:
		return bgpq4_print_nokia_oaspath(f, b);
	case V_NOKIA_MD:
		return bgpq4_print_nokia_md_oaspath(f, b);
	case V_HUAWEI:
		return bgpq4_print_huawei_oaspath(f, b);
	case V_ARISTA:
		return bgpq4_print_cisco_oaspath(f, b);
	default:
		sx_report(SX_FATAL,"Unknown vendor %i\n", b->vendor);
	}

	return 0;
}

int
bgpq4_print_asset(FILE* f, struct bgpq_expander* b)
{
	switch (b->vendor) {
	case V_JSON:
		return bgpq4_print_json_aspath(f, b);
	case V_OPENBGPD:
		return bgpq4_print_openbgpd_asset(f, b);
	case V_BIRD:
		return bgpq4_print_bird_aspath(f, b);
	default:
		sx_report(SX_FATAL, "as-sets (-t) supported for JSON, "
		    "OpenBGPD, and BIRD only\n");
		return -1;
	}
}

void
bgpq4_print_jprefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

	if (n->isGlue)
		return;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));
	fprintf(f,"    %s;\n", prefix);
}

static int   needscomma = 0;

void
bgpq4_print_json_prefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

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

int
bgpq4_print_json_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k;

	fprintf(f, "{\"%s\": [", b->name ? b->name : "NN");

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {

				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (!nc) {
						fprintf(f, "%s\n  %u",
						    needscomma ? "," : "",
						    k * 65536 + i * 8 + j);
						needscomma = 1;
					} else {
						fprintf(f, "%s%u",
						    needscomma ? "," : "",
						    k * 65536 + i * 8 + j);
						needscomma = 1;
					}

					nc++;

					if (nc == b->aswidth)
						nc = 0;
				}
			}
		}
	}

	fprintf(f,"\n]}\n");

	return 0;
}

void
bgpq4_print_bird_prefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

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

int
bgpq4_print_bird_aspath(FILE* f, struct bgpq_expander* b)
{
	int nc = 0, i, j, k, empty = 1;
	char buffer[2048];
	snprintf(buffer, sizeof(buffer), "%s = [", b->name ? b->name : "NN");

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {

				if (b->asn32s[k][i] & (0x80 >> j)) {

					if (buffer[0])
						fprintf(f, "%s", buffer);

					buffer[0] = 0;

					if (!nc) {
						fprintf(f, "%s%u",
						    empty ? "" : ",\n    ",
						    k * 65536 + i * 8 + j);
						empty = 0;
					} else {
						fprintf(f, ", %u",
						    k * 65536 + i * 8 + j);
					}

					nc++;

					if (nc == b->aswidth)
						nc = 0;
				}
			}
		}
	}

	if (!empty)
		fprintf(f, "];\n");

	return 0;
}

void
bgpq4_print_openbgpd_prefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

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

int
bgpq4_print_openbgpd_asset(FILE* f, struct bgpq_expander* b)
{
	int i, j, k, nc = 0;

	fprintf(f, "as-set %s {", b->name ? b->name : "NN");

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {
					fprintf(f, "%s%u",
					    nc == 0 ? "\n\t" : " ",
					    k * 65536 + i * 8 + j);

					nc++;

					if (nc == b->aswidth)
						nc = 0;
				}
			}
		}
	}

	fprintf(f, "\n}\n");

	return 0;
}

int
bgpq4_print_openbgpd_aspath(FILE* f, struct bgpq_expander* b)
{
	int i, j, k, lineNo = 0;

	for (k = 0; k < 65536; k++) {

		if (!b->asn32s[k])
			continue;

		for (i = 0; i < 8192; i++) {
			for (j = 0; j < 8; j++) {
				if (b->asn32s[k][i] & (0x80 >> j)) {
					fprintf(f, "allow from AS %u AS %u\n",
					    b->asnumber, k * 65536 + i * 8 + j);
					lineNo++;
				}
			}
		}
	}

	if (!lineNo)
		fprintf(f, "deny from AS %u\n", b->asnumber);

	return 0;
}

static int jrfilter_prefixed = 1;

void
bgpq4_print_jrfilter(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "    %s%s exact;\n",
		    jrfilter_prefixed ? "route-filter " : "", prefix);
	} else {
		if (n->aggregateLow>n->prefix->masklen) {
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

void
bgpq4_print_cprefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128], seqno[16] = "";
	FILE* f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (seq)
		snprintf(seqno, sizeof(seqno), " seq %i", seq++);

	if (n->isAggregate) {
		if (n->aggregateLow>n->prefix->masklen) {
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

void
bgpq4_print_cprefixxr(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (n->isAggregate) {
		if (n->aggregateLow>n->prefix->masklen) {
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

void
bgpq4_print_hprefix(struct sx_radix_node* n, void* ff)
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

void
bgpq4_print_eprefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128], seqno[16] = "";
	FILE* f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	snprintf(seqno, sizeof(seqno), " seq %i", seq++);

	if (n->isAggregate) {
		if (n->aggregateLow>n->prefix->masklen) {
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


void
bgpq4_print_ceacl(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;
	char* c;
	uint32_t netmask = 0xfffffffful;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	c = strchr(prefix, '/');

	if (c)
		*c = 0;

	if (n->prefix->masklen == 32) {
		netmask = 0;
	} else {
	 	netmask <<= (32 - n->prefix->masklen);
		netmask &= 0xfffffffful;
	}
	netmask = htonl(netmask);

	if (n->isAggregate) {
		unsigned long mask = 0xfffffffful, wildaddr, wild2addr, wildmask;
		int masklen = n->aggregateLow;
		wildaddr = 0xfffffffful >> n->prefix->masklen;

		if (n->aggregateHi == 32) {
			wild2addr = 0;
		} else {
			wild2addr = 0xfffffffful >> n->aggregateHi;
		}
		wildaddr = wildaddr &(~wild2addr);

		if (masklen == 32)
			mask = 0xfffffffful;

		else
			mask = 0xfffffffful & (0xfffffffful << (32 - masklen));

		if (n->aggregateHi == 32)
			wild2addr = 0;
		else
			wild2addr = 0xfffffffful >> n->aggregateHi;

		wildmask = (0xfffffffful >> n->aggregateLow) & (~wild2addr);

		mask = htonl(mask);
		wildaddr = htonl(wildaddr);
		wildmask = htonl(wildmask);

		if (wildaddr) {
			fprintf(f, " permit ip %s ",
			    inet_ntoa(n->prefix->addr.addr));
			fprintf(f, "%s ",
			    inet_ntoa(*(struct in_addr*) & wildaddr));
		} else {
			fprintf(f, " permit ip host %s ",
			    inet_ntoa(n->prefix->addr.addr));
		}

		if (wildmask) {
			fprintf(f, "%s ",
			    inet_ntoa(*(struct in_addr*) & mask));
			fprintf(f, "%s\n",
			    inet_ntoa(*(struct in_addr*) & wildmask));
		} else {
			fprintf(f, "host %s\n",
			    inet_ntoa(*(struct in_addr*) & mask));
		}
	} else {
		fprintf(f, " permit ip host %s host %s\n", prefix,
		    inet_ntoa(*(struct in_addr*) & netmask));
	}

checkSon:
	if (n->son)
		bgpq4_print_ceacl(n->son, ff);
}

void
bgpq4_print_nokia_ipfilter(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

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

void
bgpq4_print_nokia_md_ipfilter(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

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

void
bgpq4_print_nokia_prefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "    prefix %s exact\n", prefix);
	} else {
		if (n->aggregateLow>n->prefix->masklen) {
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

void
bgpq4_print_nokia_md_prefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

	if (n->isGlue)
		goto checkSon;

	if (!f)
		f = stdout;

	sx_prefix_snprintf(n->prefix, prefix, sizeof(prefix));

	if (!n->isAggregate) {
		fprintf(f, "    prefix %s type exact {\n    }\n", prefix);
	} else {
		if (n->aggregateLow>n->prefix->masklen) {
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

int
bgpq4_print_juniper_prefixlist(FILE* f, struct bgpq_expander* b)
{
	fprintf(f, "policy-options {\nreplace:\n prefix-list %s {\n",
	    b->name ? b->name : "NN");

	sx_radix_tree_foreach(b->tree, bgpq4_print_jprefix, f);

	fprintf(f, " }\n}\n");

	return 0;
}

int
bgpq4_print_juniper_routefilter(FILE* f, struct bgpq_expander* b)
{
	char* c = NULL;

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

	return 0;
}

int
bgpq4_print_openbgpd_prefixlist(FILE* f, struct bgpq_expander* b)
{
	bname = b->name ? b->name : "NN";

	if (sx_radix_tree_empty(b->tree)) {
		fprintf(f, "# generated prefix-list %s (AS %u) is empty\n",
		    bname, b->asnumber);
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

	return 0;
}

int
bgpq4_print_openbgpd_prefixset(FILE* f, struct bgpq_expander* b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "prefix-set %s {", bname);

	if (!sx_radix_tree_empty(b->tree))
		sx_radix_tree_foreach(b->tree, bgpq4_print_openbgpd_prefix, f);

	fprintf(f, "\n}\n");

	return 0;
}

int
bgpq4_print_cisco_prefixlist(FILE* f, struct bgpq_expander* b)
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

	return 0;
}

int
bgpq4_print_ciscoxr_prefixlist(FILE* f, struct bgpq_expander* b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "no prefix-set %s\nprefix-set %s\n", bname, bname);

	sx_radix_tree_foreach(b->tree, bgpq4_print_cprefixxr, f);

	fprintf(f, "\nend-set\n");

	return 0;
}

int
bgpq4_print_json_prefixlist(FILE* f, struct bgpq_expander* b)
{
	fprintf(f, "{ \"%s\": [",
		b->name ? b->name : "NN");

	sx_radix_tree_foreach(b->tree, bgpq4_print_json_prefix, f);

	fprintf(f,"\n] }\n");

	return 0;
}

int
bgpq4_print_bird_prefixlist(FILE* f, struct bgpq_expander* b)
{
	if (!sx_radix_tree_empty(b->tree)) {
		fprintf(f,"%s = [",
		    b->name ? b->name : "NN");
		sx_radix_tree_foreach(b->tree, bgpq4_print_bird_prefix, f);
		fprintf(f, "\n];\n");
	} else {
		SX_DEBUG(debug_expander, "skip empty prefix-list in BIRD format\n");
	}

	return 0;
}

int
bgpq4_print_huawei_prefixlist(FILE* f, struct bgpq_expander* b)
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

	return 0;
}

int
bgpq4_print_arista_prefixlist(FILE* f, struct bgpq_expander* b)
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

	return 0;
}

struct fpcbdata {
	FILE* f;
	struct bgpq_expander* b;
};

void
bgpq4_print_format_prefix(struct sx_radix_node* n, void* ff)
{
	struct fpcbdata* fpc = (struct fpcbdata*)ff;
	FILE* f = fpc->f;
	struct bgpq_expander* b = fpc->b;

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


int
bgpq4_print_format_prefixlist(FILE* f, struct bgpq_expander* b)
{
	struct fpcbdata ff = {.f=f, .b=b};
	int len = strlen(b->format);

	sx_radix_tree_foreach(b->tree, bgpq4_print_format_prefix, &ff);

	// Add newline if format doesn't already end with one.
	if (len < 2 ||
	    !(b->format[len-2] == '\\' && b->format[len-1] == 'n'))
		fprintf(f, "\n");

	return 0;
}

int
bgpq4_print_nokia_prefixlist(FILE* f, struct bgpq_expander* b)
{
	bname = b->name ? b->name : "NN";
	fprintf(f,"configure router policy-options\nbegin\nno prefix-list \"%s\"\n",
		bname);
	fprintf(f,"prefix-list \"%s\"\n", bname);
	sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_prefix, f);
	fprintf(f,"exit\ncommit\n");
	return 0;
}

int
bgpq4_print_cisco_eacl(FILE* f, struct bgpq_expander* b)
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

	return 0;
}

int
bgpq4_print_nokia_ipprefixlist(FILE* f, struct bgpq_expander* b)
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

	return 0;
}

int
bgpq4_print_nokia_md_prefixlist(FILE* f, struct bgpq_expander* b)
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

	return 0;
}

int
bgpq4_print_nokia_md_ipprefixlist(FILE* f, struct bgpq_expander* b)
{
	bname = b->name ? b->name : "NN";

	fprintf(f, "/configure policy-options\ndelete prefix-list \"%s\"\n",
	    bname);

	fprintf(f, "prefix-list \"%s\" {\n", bname);

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_nokia_md_prefix, f);
	}

	fprintf(f,"}\n");

	return 0;
}

void
bgpq4_print_kprefix(struct sx_radix_node* n, void* ff)
{
	char prefix[128];
	FILE* f = (FILE*)ff;

	if (!f)
		f = stdout;

	if (n->isGlue)
		goto checkSon;

	sx_prefix_snprintf_sep(n->prefix, prefix, sizeof(prefix), "/");

	if (n->isAggregate) {
		if (n->aggregateLow>n->prefix->masklen) {
			fprintf(f,"/routing filter add action=accept chain=\""
			    "%s-%s\" prefix=%s prefix-length=%d-%d\n",
			    bname ? bname : "NN",
			    n->prefix->family == AF_INET ? "V4" : "V6",
			    prefix, n->aggregateLow, n->aggregateHi);
		} else {
			fprintf(f,"/routing filter add action=accept chain=\""
			    "%s-%s\" prefix=%s prefix-length=%d\n",
			    bname ? bname : "NN",
			    n->prefix->family == AF_INET ? "V4" : "V6",
			    prefix, n->aggregateHi);
		}
	} else {
		fprintf(f,"/routing filter add action=accept chain=\""
		    "%s-%s\" prefix=%s\n",
		    bname ? bname : "NN",
		    n->prefix->family == AF_INET ? "V4" : "V6",
		    prefix);
	}

checkSon:
	if (n->son)
		bgpq4_print_kprefix(n->son, ff);
}

int
bgpq4_print_mikrotik_prefixlist(FILE* f, struct bgpq_expander* b)
{
	bname = b->name ? b->name : "NN";

	if (!sx_radix_tree_empty(b->tree)) {
		sx_radix_tree_foreach(b->tree, bgpq4_print_kprefix, f);
	} else {
		fprintf(f, "# generated prefix-list %s is empty\n", bname);
	}

	return 0;
}

int
bgpq4_print_prefixlist(FILE* f, struct bgpq_expander* b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		return bgpq4_print_juniper_prefixlist(f, b);
	case V_CISCO:
		return bgpq4_print_cisco_prefixlist(f, b);
	case V_CISCO_XR:
		return bgpq4_print_ciscoxr_prefixlist(f, b);
	case V_JSON:
		return bgpq4_print_json_prefixlist(f, b);
	case V_BIRD:
		return bgpq4_print_bird_prefixlist(f, b);
	case V_OPENBGPD:
		return bgpq4_print_openbgpd_prefixlist(f, b);
	case V_FORMAT:
		return bgpq4_print_format_prefixlist(f, b);
	case V_NOKIA:
		return bgpq4_print_nokia_prefixlist(f, b);
	case V_NOKIA_MD:
		return bgpq4_print_nokia_md_ipprefixlist(f, b);
	case V_HUAWEI:
		return bgpq4_print_huawei_prefixlist(f, b);
	case V_MIKROTIK:
		return bgpq4_print_mikrotik_prefixlist(f, b);
	case V_ARISTA:
		return bgpq4_print_arista_prefixlist(f, b);
	}

	return 0;
}

int
bgpq4_print_eacl(FILE* f, struct bgpq_expander* b)
{
	switch (b->vendor) {
	case V_JUNIPER:
		return bgpq4_print_juniper_routefilter(f, b);
	case V_CISCO:
		return bgpq4_print_cisco_eacl(f, b);
	case V_CISCO_XR:
		sx_report(SX_FATAL, "unreachable point\n");
	case V_JSON:
		sx_report(SX_FATAL, "unreachable point\n");
	case V_BIRD:
		sx_report(SX_FATAL, "unreachable point\n");
	case V_OPENBGPD:
		return bgpq4_print_openbgpd_prefixset(f, b);
	case V_FORMAT:
		sx_report(SX_FATAL, "unreachable point\n");
	case V_NOKIA:
		return bgpq4_print_nokia_ipprefixlist(f, b);
	case V_NOKIA_MD:
		return bgpq4_print_nokia_md_prefixlist(f, b);
	case V_MIKROTIK:
		return sx_report(SX_FATAL, "unreachable point\n");
	case V_HUAWEI:
		return sx_report(SX_FATAL, "unreachable point\n");
	case V_ARISTA:
		return bgpq4_print_cisco_eacl(f, b);
	}

	return 0;
}

int
bgpq4_print_juniper_route_filter_list(FILE* f, struct bgpq_expander* b)
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

	return 0;
}

int
bgpq4_print_route_filter_list(FILE* f, struct bgpq_expander* b)
{
	switch(b->vendor) {
	case V_JUNIPER:
		return bgpq4_print_juniper_route_filter_list(f, b);
	default:
		sx_report(SX_FATAL, "unreachable point\n");
	}

	return 0;
}
