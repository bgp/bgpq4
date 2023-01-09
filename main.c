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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "extern.h"
#include "sx_report.h"

extern int debug_expander;
extern int debug_aggregation;
extern int pipelining;
extern int expand_special_asn;

static int
usage(int ecode)
{
	printf("\nUsage: bgpq4 [-h host[:port]] [-S sources] [-E|G|H <num>"
	    "|f <num>|t] [-46ABbdJjKNnpwXz] [-R len] <OBJECTS> ... "
	    "[EXCEPT <OBJECTS> ...]\n");
	printf("\nVendor targets:\n");
	printf(" no option : Cisco IOS Classic (default)\n");
	printf(" -X        : Cisco IOS XR\n");
	printf(" -U        : Huawei\n");
	printf(" -u        : Huawei XPL\n");
	printf(" -j        : JSON\n");
	printf(" -J        : Juniper Junos\n");
	printf(" -K        : MikroTik RouterOSv6\n");
	printf(" -K7       : MikroTik RouterOSv7\n");
	printf(" -b        : NIC.CZ BIRD\n");
	printf(" -N        : Nokia SR OS (Classic CLI)\n");
	printf(" -n        : Nokia SR OS (MD-CLI)\n");
	printf(" -B        : OpenBSD OpenBGPD\n");
	printf(" -e        : Arista EOS\n");
	printf(" -F fmt    : User defined format (example: '-F %%n/%%l')\n");

	printf("\nInput filters:\n");
	printf(" -4        : generate IPv4 prefix-lists (default)\n");
	printf(" -6        : generate IPv6 prefix-lists\n");
	printf(" -m len    : maximum prefix length (default: 32 for IPv4, "
		"128 for IPv6)\n");
	printf(" -L depth  : limit recursion depth (default: unlimited)\n"),
	printf(" -S sources: only use specified IRR sources, in the specified "
	    "order (comma separated)\n");
	printf(" -w        : 'validate' AS numbers: accept only ones with "
		"registered routes\n");

	printf("\nOutput modifiers:\n");
	printf(" -A        : try to aggregate prefix-lists/route-filters\n");
	printf(" -E        : generate extended access-list (Cisco), "
	    "route-filter (Juniper)\n"
	    "             [ip|ipv6]-prefix-list (Nokia) or prefix-set "
	    "(OpenBGPD)\n");
	printf(" -f number : generate input as-path access-list\n");
	printf(" -G number : generate output as-path access-list\n");
	printf(" -H number : generate origin as-lists (JunOS only)\n");
	printf(" -M match  : extra match conditions for JunOS route-filters\n");
	printf(" -l name   : use specified name for generated access/prefix/.."
		" list\n");
	printf(" -R len    : allow more specific routes up to specified masklen\n");
	printf(" -r len    : allow more specific routes from masklen specified\n");
	printf(" -s        : generate sequence numbers in prefix-lists (IOS only)\n");
	printf(" -t        : generate as-sets for OpenBGPD (OpenBGPD 6.4+), BIRD "
		"and JSON formats\n");
	printf(" -z        : generate route-filter-list (Junos only)\n");
	printf(" -W len    : specify max-entries on as-path/as-list line (use 0 for "
		"infinity)\n");

	printf("\nUtility operations:\n");
	printf(" -d        : generate some debugging output\n");
	printf(" -h host   : host running IRRD software (default: rr.ntt.net)\n"
		    "             use 'host:port' to specify alternate port\n");
	printf(" -T        : disable pipelining (not recommended)\n");
	printf(" -v        : print version and exit\n");
	printf("\n" PACKAGE_NAME " version: " PACKAGE_VERSION " "
	    "(https://github.com/bgp/bgpq4)\n");
	exit(ecode);
}

static void
version(void)
{
	printf(PACKAGE_NAME " - a versatile utility to generate BGP filters\n"
	    "version: " PACKAGE_VERSION "\n"
	    "website: https://github.com/bgp/bgpq4\n"
	    "maintainer: Job Snijders <job@sobornost.net>\n");
	exit(0);
}

static void
exclusive(void)
{
	fprintf(stderr,"-E, -F, -K , -f <asnum>, -G <asnum>, and -t are mutually"
	    " exclusive\n");
	exit(1);
}

static void
vendor_exclusive(void)
{
	fprintf(stderr, "-b (BIRD), -B (OpenBGPD), -F (formatted), -J (Junos),"
	    " -j (JSON), -K[7] (Microtik ROS), -N (Nokia SR OS Classic),"
	    " -n (Nokia SR OS MD-CLI), -U (Huawei), -u (Huawei XPL),"
	    "-e (Arista) and -X (IOS XR) options are mutually exclusive\n");
	exit(1);
}

static int
parseasnumber(struct bgpq_expander *expander, char *asnstr)
{
	char	*eon = NULL;

	expander->asnumber = strtoul(asnstr, &eon, 10);
	if (expander->asnumber < 1 || expander->asnumber > (65535ul * 65535)) {
		sx_report(SX_FATAL, "Invalid AS number: %s\n", asnstr);
		exit(1);
	}
	if (eon && *eon == '.') {
		/* -f 3.3, for example */
		uint32_t loas = strtoul(eon + 1, &eon, 10);
		if (expander->asnumber > 65535) {
			/* should prevent incorrect numbers like 65537.1 */
			sx_report(SX_FATAL,"Invalid AS number: %s\n", asnstr);
			exit(1);
		}
		if (loas < 1 || loas > 65535) {
			sx_report(SX_FATAL,"Invalid AS number: %s\n", asnstr);
			exit(1);
		}
		if (eon && *eon) {
			sx_report(SX_FATAL,"Invalid symbol in AS number: "
			    "%c (%s)\n", *eon, asnstr);
			exit(1);
		}
		expander->asnumber=(expander->asnumber << 16) + loas;
	} else if (eon && *eon) {
		sx_report(SX_FATAL,"Invalid symbol in AS number: %c (%s)\n",
			*eon, asnstr);
		exit(1);
	}
	return 0;
}

int
main(int argc, char* argv[])
{
	int c;
	struct bgpq_expander expander;
	int af = AF_INET, selectedipv4 = 0, exceptmode = 0;
	int widthSet = 0, aggregate = 0, refine = 0, refineLow = 0;
	unsigned long maxlen = 0;

#ifdef HAVE_PLEDGE
	if (pledge("stdio inet dns", NULL) == -1) {
		sx_report(SX_ERROR, "pledge() failed");
		exit(1);
	}
#endif

	bgpq_expander_init(&expander, af);

	if (getenv("IRRD_SOURCES"))
		expander.sources=getenv("IRRD_SOURCES");

	while ((c = getopt(argc, argv,
	    "467a:AbBdDEeF:S:jJKf:l:L:m:M:NnpW:r:R:G:H:tTh:UuwXsvz")) != EOF) {
	switch (c) {
	case '4':
		/* do nothing, expander already configured for IPv4 */
		if (expander.family == AF_INET6) {
			sx_report(SX_FATAL, "-4 and -6 are mutually "
			    "exclusive\n");
			exit(1);
		}
		selectedipv4 = 1;
		break;
	case '6':
		if (selectedipv4) {
			sx_report(SX_FATAL, "-4 and -6 are mutually "
			    "exclusive\n");
			exit(1);
		}
		af = AF_INET6;
		expander.family = AF_INET6;
		expander.tree->family = AF_INET6;
		break;
	case '7':
		if (expander.vendor != V_MIKROTIK6) {
			sx_report(SX_FATAL, "'7' can only be used after -K\n");
			exit(1);
		}
		expander.vendor = V_MIKROTIK7;
		break;
	case 'a':
		parseasnumber(&expander, optarg);
		break;
	case 'A':
		if (aggregate)
			debug_aggregation++;
		aggregate = 1;
		break;
	case 'b':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_BIRD;
		break;
	case 'B':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_OPENBGPD;
		break;
	case 'd':
		debug_expander++;
		break;
	case 'E':
		if (expander.generation)
			exclusive();
		expander.generation = T_EACL;
		break;
	case 'e':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_ARISTA;
		expander.sequence = 1;
		break;
	case 'F':
		if (expander.vendor)
			exclusive();
		expander.vendor = V_FORMAT;
		expander.format = optarg;
		break;
	case 'f':
		if (expander.generation)
			exclusive();
		expander.generation = T_ASPATH;
		parseasnumber(&expander, optarg);
		break;
	case 'G':
		if (expander.generation)
			exclusive();
		expander.generation = T_OASPATH;
		parseasnumber(&expander, optarg);
		break;
	case 'H':
		if (expander.generation)
			exclusive();
		expander.generation = T_ASLIST;
		parseasnumber(&expander, optarg);
		break;
	case 'h':
		{
			char *d = strchr(optarg, ':');
			expander.server = optarg;
			if (d) {
				*d = 0;
				expander.port = d + 1;
			}
		}
		break;
	case 'J':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_JUNIPER;
		break;
	case 'j':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_JSON;
		break;
	case 'K':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_MIKROTIK6;
		break;
	case 'r':
		refineLow = strtoul(optarg, NULL, 10);
		if (!refineLow) {
			sx_report(SX_FATAL, "Invalid refineLow value:"
			    " %s\n", optarg);
			exit(1);
		}
		break;
	case 'R':
		refine = strtoul(optarg, NULL, 10);
		if (!refine) {
			sx_report(SX_FATAL,"Invalid refine length:"
			    " %s\n", optarg);
			exit(1);
		}
		break;
	case 'l':
		expander.name = optarg;
		break;
	case 'L':
		expander.maxdepth = strtol(optarg, NULL, 10);
		if (expander.maxdepth < 1) {
			sx_report(SX_FATAL, "Invalid maximum recursion"
			    " (-L): %s\n", optarg);
			exit(1);
		}
		break;
	case 'm':
		maxlen=strtoul(optarg, NULL, 10);
		if (!maxlen) {
			sx_report(SX_FATAL, "Invalid maxlen (-m): %s\n",
			    optarg);
			exit(1);
		}
		break;
	case 'M':
		{
			char	*mc, *md;
			expander.match = strdup(optarg);
			mc = md = expander.match;
			while (*mc) {
				if (*mc == '\\') {
					if (*(mc + 1) == '\n') {
						*md = '\n';
						md++;
						mc += 2;
					} else if (*(mc + 1) == 'r') {
						*md = '\r';
						md++;
						mc += 2;
					} else if (*(mc + 1) == 't') {
						*md = '\t';
						md++;
						mc += 2;
					} else if (*(mc + 1) == '\\') {
						*md = '\\';
						md++;
						mc += 2;
					} else {
						sx_report(SX_FATAL, "Unsupported"
						    " escape \%c (0x%2.2x) in "
						    "'%s'\n",
						    isprint(*mc) ? *mc : 20,
						    *mc, optarg);
						exit(1);
					}
				} else {
					if (mc != md) {
						*md = *mc;
					}
					md++;
					mc++;
				}
			}
			*md = 0;
		}
		break;
	case 'N':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_NOKIA;
		break;
	case 'n':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_NOKIA_MD;
		break;
	case 'p':
		expand_special_asn = 1;
		break;
	case 't':
		if (expander.generation)
			exclusive();
		expander.generation = T_ASSET;
		break;
	case 'T':
		pipelining = 0;
		break;
	case 's':
		expander.sequence = 1;
		break;
	case 'S':
		expander.sources = optarg;
		break;
	case 'U':
		if (expander.vendor)
			exclusive();
		expander.vendor = V_HUAWEI;
		break;
	case 'u':
		if (expander.vendor)
			exclusive();
		expander.vendor = V_HUAWEI_XPL;
		break;
	case 'W':
		expander.aswidth = atoi(optarg);
		if (expander.aswidth < 0) {
			sx_report(SX_FATAL,"Invalid as-width: %s\n", optarg);
			exit(1);
		}
		widthSet = 1;
		break;
	case 'w':
		expander.validate_asns = 1;
		break;
	case 'X':
		if (expander.vendor)
			vendor_exclusive();
		expander.vendor = V_CISCO_XR;
		break;
	case 'v':
		version();
		break;
	case 'z':
		if (expander.generation)
			exclusive();
		expander.generation = T_ROUTE_FILTER_LIST;
		break;
	default:
		usage(1);
	}
	}

	argc -= optind;
	argv += optind;

	if (!widthSet) {
		if (expander.generation == T_ASPATH) {
			int vendor = expander.vendor;
			switch (vendor) {
			case V_ARISTA:
			case V_CISCO:
			case V_MIKROTIK6:
			case V_MIKROTIK7:
				expander.aswidth = 4;
				break;
			case V_CISCO_XR:
				expander.aswidth = 6;
				break;
			case V_JUNIPER:
			case V_NOKIA:
			case V_NOKIA_MD:
				expander.aswidth = 8;
				break;
			case V_BIRD:
				expander.aswidth = 10;
				break;
			}
		} else if (expander.generation == T_OASPATH) {
			int vendor = expander.vendor;
			switch (vendor) {
			case V_ARISTA:
			case V_CISCO:
				expander.aswidth = 5;
				break;
			case V_CISCO_XR:
				expander.aswidth = 7;
				break;
			case V_JUNIPER:
			case V_NOKIA:
			case V_NOKIA_MD:
				expander.aswidth = 8;
				break;
			}
		} else if (expander.generation == T_ASLIST) {
			int vendor = expander.vendor;
			switch (vendor) {
			case V_JUNIPER:
				expander.aswidth = 8;
				break;
			}
		}
	}

	if (!expander.generation)
		expander.generation = T_PREFIXLIST;

	if (expander.vendor == V_CISCO_XR
	    && expander.generation != T_PREFIXLIST
	    && expander.generation != T_ASPATH
	    && expander.generation != T_OASPATH) {
		sx_report(SX_FATAL, "Sorry, only prefix-sets and as-paths "
		    "supported for IOS XR\n");
	}
	if (expander.vendor == V_BIRD
	    && expander.generation != T_PREFIXLIST
	    && expander.generation != T_ASPATH
	    && expander.generation != T_ASSET) {
		sx_report(SX_FATAL, "Sorry, only prefix-lists and as-paths/as-sets "
		    "supported for BIRD output\n");
	}
	if (expander.vendor == V_JSON
	    && expander.generation != T_PREFIXLIST
	    && expander.generation != T_ASPATH
	    && expander.generation != T_ASSET) {
		sx_report(SX_FATAL, "Sorry, only prefix-lists and as-paths/as-sets "
		    "supported for JSON output\n");
	}

	if (expander.vendor == V_FORMAT
	    && expander.generation != T_PREFIXLIST)
		sx_report(SX_FATAL, "Sorry, only prefix-lists supported in formatted "
		    "output\n");

	if (expander.vendor == V_HUAWEI
	    && expander.generation != T_ASPATH
	    && expander.generation != T_OASPATH
	    && expander.generation != T_PREFIXLIST)
		sx_report(SX_FATAL, "Sorry, only as-paths and prefix-lists supported "
		    "for Huawei output\n");

	if (expander.generation == T_ROUTE_FILTER_LIST
	    && expander.vendor != V_JUNIPER)
		sx_report(SX_FATAL, "Route-filter-lists (-z) supported for Juniper (-J)"
		    " output only\n");

	if (expander.generation == T_ASSET
	    && expander.vendor != V_JSON
	    && expander.vendor != V_OPENBGPD
	    && expander.vendor != V_BIRD)
		sx_report(SX_FATAL, "As-Sets (-t) supported for JSON (-j), OpenBGPD "
		    "(-B) and BIRD (-b) output only\n");

	if (aggregate
	    && expander.vendor == V_JUNIPER
	    && expander.generation == T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, aggregation (-A) does not work in"
		    " Juniper prefix-lists\nYou can try route-filters (-E) "
		    "or route-filter-lists (-z) instead of prefix-lists\n.");
		exit(1);
	}

	if (aggregate
	    && (expander.vendor == V_NOKIA_MD || expander.vendor == V_NOKIA)
	    && expander.generation != T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, aggregation (-A) is not supported with "
		    "ip-prefix-lists (-E) on Nokia.\n");
		exit(1);
	}

	if (refine
	    && (expander.vendor == V_NOKIA_MD || expander.vendor == V_NOKIA)
	    && expander.generation != T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, more-specifics (-R) is not supported with "
		    "ip-prefix-lists (-E) on Nokia.\n");
		exit(1);
	}

	if (refineLow
	     && (expander.vendor == V_NOKIA_MD || expander.vendor == V_NOKIA)
	     && expander.generation != T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, more-specifics (-r) is not supported with "
		    "ip-prefix-lists (-E) on Nokia.\n");
		exit(1);
	}

	if (aggregate && expander.generation < T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, aggregation (-A) used only for prefix-"
		    "lists, extended access-lists and route-filters\n");
		exit(1);
	}

	if (expander.sequence
	    && (expander.vendor != V_CISCO && expander.vendor != V_ARISTA)) {
		sx_report(SX_FATAL, "Sorry, prefix-lists sequencing (-s) supported"
		    " only for IOS and EOS\n");
		exit(1);
	}

	if (expander.sequence && expander.generation < T_PREFIXLIST) {
		sx_report(SX_FATAL, "Sorry, prefix-lists sequencing (-s) can't be "
		    " used for non prefix-list\n");
		exit(1);
	}

	if (refineLow && !refine) {
		if (expander.family == AF_INET)
			refine = 32;
		else
			refine = 128;
	}

	if (refineLow && refineLow > refine)
		sx_report(SX_FATAL, "Incompatible values for -r %u and -R %u\n",
		    refineLow, refine);

	if (refine || refineLow) {
		if (expander.family == AF_INET6 && refine > 128) {
			sx_report(SX_FATAL, "Invalid value for refine(-R): %u (1-128 for"
			    " IPv6)\n", refine);
		} else if (expander.family == AF_INET6 && refineLow > 128) {
			sx_report(SX_FATAL, "Invalid value for refineLow(-r): %u (1-128 for"
			    " IPv6)\n", refineLow);
		} else if (expander.family == AF_INET && refine > 32) {
			sx_report(SX_FATAL, "Invalid value for refine(-R): %u (1-32 for"
			    " IPv4)\n", refine);
		} else if (expander.family == AF_INET && refineLow > 32) {
			sx_report(SX_FATAL, "Invalid value for refineLow(-r): %u (1-32 for"
			    " IPv4)\n", refineLow);
		}

		if (expander.vendor == V_JUNIPER && expander.generation == T_PREFIXLIST) {
			if (refine) {
				sx_report(SX_FATAL, "Sorry, more-specific filters (-R %u) "
				    "is not supported for Juniper prefix-lists.\n"
				    "Use router-filters (-E) or route-filter-lists (-z) "
				    "instead\n", refine);
			} else {
				sx_report(SX_FATAL, "Sorry, more-specific filters (-r %u) "
				    "is not supported for Juniper prefix-lists.\n"
				    "Use route-filters (-E) or route-filter-lists (-z) "
				    "instead\n", refineLow);
			}
		}

		if (expander.generation < T_PREFIXLIST) {
			if (refine)
				sx_report(SX_FATAL, "Sorry, more-specific filter (-R %u) "
				    "supported only with prefix-list generation\n", refine);
			else
				sx_report(SX_FATAL, "Sorry, more-specific filter (-r %u) "
				    "supported only with prefix-list generation\n", refineLow);
		}
	}

	if (maxlen) {
		if ((expander.family == AF_INET6 && maxlen > 128)
		   || (expander.family == AF_INET && maxlen > 32)) {
			sx_report(SX_FATAL, "Invalid value for max-prefixlen: %lu (1-128 "
			    "for IPv6, 1-32 for IPv4)\n", maxlen);
			exit(1);
		} else if ((expander.family == AF_INET6 && maxlen < 128)
		    || (expander.family == AF_INET  && maxlen < 32)) {
			/*
			 * inet6/128 and inet4/32 does not make sense - all
			 * routes will be accepted, so save some CPU cycles :)
			 */
			expander.maxlen = maxlen;
		}
	} else if (expander.family == AF_INET)
		expander.maxlen = 32;
	else if (expander.family == AF_INET6)
		expander.maxlen = 128;

	if (expander.generation == T_EACL && expander.vendor == V_CISCO
	    && expander.family == AF_INET6) {
		sx_report(SX_FATAL,"Sorry, ipv6 access-lists not supported "
		    "for Cisco yet.\n");
	}

	if (expander.match != NULL
	    && (expander.vendor != V_JUNIPER || expander.generation != T_EACL)) {
		sx_report(SX_FATAL, "Sorry, extra match conditions (-M) can be used "
		    "only with Juniper route-filters\n");
	}

	if ((expander.generation == T_ASPATH
	    || expander.generation == T_OASPATH
	    || expander.generation == T_ASLIST)
	    && af != AF_INET && !expander.validate_asns) {
		sx_report(SX_FATAL, "Sorry, -6 makes no sense with as-path (-f/-G) or as-list (-H) "
		    "generation\n");
	}

	if (expander.validate_asns
	    && expander.generation != T_ASPATH
	    && expander.generation != T_OASPATH
	    && expander.generation != T_ASLIST) {
		sx_report(SX_FATAL, "Sorry, -w makes sense only for as-path "
		    "(-f/-G) generation\n");
	}

	if (!argv[0])
		usage(1);

	while (argv[0]) {
		char *obj = argv[0];
		char *delim = strstr(argv[0], "::");
		if (delim) {
			expander.usesource = 1;
			obj = delim + 2;
		}
		if (!strcmp(argv[0], "EXCEPT")) {
			exceptmode = 1;
		} else if (exceptmode) {
			bgpq_expander_add_stop(&expander, argv[0]);
		} else if (!strncasecmp(obj, "AS-", 3)) {
			bgpq_expander_add_asset(&expander, argv[0]);
		} else if (!strncasecmp(obj, "RS-", 3)) {
			bgpq_expander_add_rset(&expander, argv[0]);
		} else if (!strncasecmp(obj, "AS", 2)) {
			char *ec;
			if ((ec = strchr(obj, ':'))) {
				if (!strncasecmp(ec + 1, "AS-", 3)) {
					bgpq_expander_add_asset(&expander, argv[0]);
				} else if (!strncasecmp(ec + 1, "RS-", 3)) {
					bgpq_expander_add_rset(&expander, argv[0]);
				} else {
					SX_DEBUG(debug_expander,"Unknown sub-as"
					    " object %s\n", argv[0]);
				}
			} else {
				bgpq_expander_add_as(&expander, argv[0]);
			}
		} else {
			char *ec = strchr(argv[0], '^');
			if (!ec && !bgpq_expander_add_prefix(&expander, argv[0])) {
				sx_report(SX_ERROR, "Unable to add prefix %s "
				    "(bad prefix or address-family)\n", argv[0]);
				exit(1);
			} else if (ec && !bgpq_expander_add_prefix_range(&expander,
				    argv[0])) {
				sx_report(SX_ERROR, "Unable to add prefix-range "
				    "%s (bad range or address-family)\n",
				    argv[0]);
				exit(1);
			}
		}
		argv++;
		argc--;
	}

	if (!bgpq_expand(&expander))
		exit(1);

	if (refine)
		sx_radix_tree_refine(expander.tree, refine);

	if (refineLow)
		sx_radix_tree_refineLow(expander.tree, refineLow);

	if (aggregate)
		sx_radix_tree_aggregate(expander.tree);

	switch (expander.generation) {
		case T_NONE:
			sx_report(SX_FATAL,"Unreachable point");
			exit(1);
		case T_ASPATH:
			bgpq4_print_aspath(stdout, &expander);
			break;
		case T_OASPATH:
			bgpq4_print_oaspath(stdout, &expander);
			break;
		case T_ASLIST:
			bgpq4_print_aslist(stdout, &expander);
			break;
		case T_ASSET:
			bgpq4_print_asset(stdout, &expander);
			break;
		case T_PREFIXLIST:
			bgpq4_print_prefixlist(stdout, &expander);
			break;
		case T_EACL:
			bgpq4_print_eacl(stdout, &expander);
			break;
		case T_ROUTE_FILTER_LIST:
			bgpq4_print_route_filter_list(stdout, &expander);
			break;
	}

        expander_freeall(&expander);

	return 0;
}
