# NAME

**bgpq4** - bgp filtering automation tool

# SYNOPSIS

**bgpq4**
\[**-h**&nbsp;*host\[:port]*]
\[**-S**&nbsp;*sources*]
\[**-EPz**]
\[**-f**&nbsp;*asn*&nbsp;|
**-F**&nbsp;*fmt*&nbsp;|
**-G**&nbsp;*asn*
**-H**&nbsp;*asn*
**-t**]
\[**-46ABbDdJjNnsXU**]
\[**-a**&nbsp;*asn*]
\[**-r**&nbsp;*len*]
\[**-R**&nbsp;*len*]
\[**-m**&nbsp;*max*]
\[**-W**&nbsp;*len*]
*OBJECTS*
\[...]
\[EXCEPT&nbsp;OBJECTS]

# DESCRIPTION

The
**bgpq4**
utility is used to generate configurations (prefix-lists, extended
access-lists, policy-statement terms and as-path lists) based on IRR data.

It's options are as follows:

**-4**

> generate IPv4 prefix/access-lists (default).

**-6**

> generate IPv6 prefix/access-lists (IPv4 by default).

**-A**

> try to aggregate prefix-lists as much as possible (not all output
> formats supported).

**-a** *asn*

> specify what asn shall be denied in case of empty prefix-list (OpenBGPD)

**-B**

> generate output in OpenBGPD format (default: Cisco)

**-b**

> generate output in BIRD format (default: Cisco).

**-d**

> enable some debugging output.

**-e**

> generate output in Arista EOS format (default: Cisco).

**-E**

> generate extended access-list (Cisco), policy-statement term using
> route-filters (Juniper), \[ip|ipv6]-prefix-list (Nokia) or prefix-sets
> (OpenBGPd).

**-f** *number*

> generate input as-path access-list.

**-F** *fmt*

> generate output in user-defined format.

**-G** *number*

> generate output as-path access-list.

**-H** *number*

> generate output as-list for JunOS 21.3R1+ `as-path-origin` filter (JunOS only)

**-h** *host\[:port]*

> host running IRRD database (default: rr.ntt.net).

**-J**

> generate config for Juniper (default: Cisco).

**-j**

> generate output in JSON format (default: Cisco).

**-K**

> generate config for Mikrotik (default: Cisco).

**-l** *name*

> name of generated entry.

**-L** *limit*

> limit recursion depth when expanding as-sets.

**-m** *len*

> maximum prefix-length of accepted prefixes (default: 32 for IPv4 and
> 128 for IPv6).

**-M** *match*

> extra match conditions for Juniper route-filters.

**-n**

> generate config for Nokia SR OS MD-CLI (Cisco IOS by default)

**-N**

> generate config for Nokia SR OS classic CLI (Cisco IOS by default).

**-p**

> accept routes registered for private ASNs (default: disabled)

**-P**

> generate prefix-list (default, backward compatibility).

**-r** *len*

> allow more specific routes starting with specified masklen too.

**-R** *len*

> allow more specific routes up to specified masklen too.

**-s**

> generate sequence numbers in IOS-style prefix-lists.

**-S** *sources*

> use specified sources only (recommended: RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE).

**-t**

> generate as-sets for OpenBGPd, BIRD and JSON formats.

**-T**

> disable pipelining (not recommended).

**-W** *len*

> generate as-path strings of no more than len items (use 0 for infinity).

**-U**

> generate config for Huawei devices (Cisco IOS by default)

**-u**

> generate output in Huawei XPL format.

**-X**

> generate config for Cisco IOS XR devices (plain IOS by default).

**-z**

> generate route-filter-lists (JunOS 16.2+).

*OBJECTS*

> means networks (in prefix format), autonomous systems, as-sets and route-sets.

*EXCEPT OBJECTS*

> those objects will be excluded from expansion.

# EXAMPLES

Generating named juniper prefix-filter for AS20597:

	$ bgpq4 -Jl eltel AS20597
	policy-options {
	replace:
	 prefix-list eltel {
	    81.9.0.0/20;
	    81.9.32.0/20;
	    81.9.96.0/20;
	    81.222.128.0/20;
	    81.222.192.0/18;
	    85.249.8.0/21;
	    85.249.224.0/19;
	    89.112.0.0/19;
	    89.112.4.0/22;
	    89.112.32.0/19;
	    89.112.64.0/19;
	    217.170.64.0/20;
	    217.170.80.0/20;
	 }
	}

For Cisco we can use aggregation (-A) flag to make this prefix-filter
more compact:

	$ bgpq4 -Al eltel AS20597
	no ip prefix-list eltel
	ip prefix-list eltel permit 81.9.0.0/20
	ip prefix-list eltel permit 81.9.32.0/20
	ip prefix-list eltel permit 81.9.96.0/20
	ip prefix-list eltel permit 81.222.128.0/20
	ip prefix-list eltel permit 81.222.192.0/18
	ip prefix-list eltel permit 85.249.8.0/21
	ip prefix-list eltel permit 85.249.224.0/19
	ip prefix-list eltel permit 89.112.0.0/18 ge 19 le 19
	ip prefix-list eltel permit 89.112.4.0/22
	ip prefix-list eltel permit 89.112.64.0/19
	ip prefix-list eltel permit 217.170.64.0/19 ge 20 le 20

Prefixes 89.112.0.0/19 and 89.112.32.0/19 now aggregated
into single entry 89.112.0.0/18 ge 19 le 19.

Well, for Juniper we can generate even more interesting policy-options,
using -M &lt;extra match conditions&gt;, -R &lt;len&gt; and hierarchical names:

	$ bgpq4 -AJEl eltel/specifics -r 29 -R 32 -M "community blackhole" AS20597
	policy-options {
	 policy-statement eltel {
	  term specifics {
	replace:
	   from {
	    community blackhole;
	    route-filter 81.9.0.0/20 prefix-length-range /29-/32;
	    route-filter 81.9.32.0/20 prefix-length-range /29-/32;
	    route-filter 81.9.96.0/20 prefix-length-range /29-/32;
	    route-filter 81.222.128.0/20 prefix-length-range /29-/32;
	    route-filter 81.222.192.0/18 prefix-length-range /29-/32;
	    route-filter 85.249.8.0/21 prefix-length-range /29-/32;
	    route-filter 85.249.224.0/19 prefix-length-range /29-/32;
	    route-filter 89.112.0.0/17 prefix-length-range /29-/32;
	    route-filter 217.170.64.0/19 prefix-length-range /29-/32;
	   }
	  }
	 }
	}

generated policy-option term now allows all specifics with prefix-length
between /29 and /32 for eltel networks if they match with special community
blackhole (defined elsewhere in configuration).

Of course, this version supports IPv6 (-6):

	$ bgpq4 -6l as-retn-6 AS-RETN6
	no ipv6 prefix-list as-retn-6
	ipv6 prefix-list as-retn-6 permit 2001:7fb:fe00::/48
	ipv6 prefix-list as-retn-6 permit 2001:7fb:fe01::/48
	[....]

and assumes your device supports 32-bit ASNs

	$ bgpq4 -Jf 112 AS-SPACENET
	policy-options {
	replace:
	 as-path-group NN {
	  as-path a0 "^112(112)*$";
	  as-path a1 "^112(.)*(1898|5539|8495|8763|8878|12136|12931|15909)$";
	  as-path a2 "^112(.)*(21358|23456|23600|24151|25152|31529|34127|34906)$";
	  as-path a3 "^112(.)*(35052|41720|43628|44450|196611)$";
	 }
	}

see \`AS196611\` in the end of the list ? That's a 32-bit ASN.

# USER-DEFINED FORMAT

If you want to generate configuration not for routers, but for some
other programs/systems, you may use user-defined formatting, like in
example below:

	$ bgpq4 -F "ipfw add pass all from %n/%l to any\n" as3254
	ipfw add pass all from 62.244.0.0/18 to any
	ipfw add pass all from 91.219.29.0/24 to any
	ipfw add pass all from 91.219.30.0/24 to any
	ipfw add pass all from 193.193.192.0/19 to any

Recognized format sequences are:

**%n**

> network

**%l**

> mask length

**%a**

> aggregate low mask length

**%A**

> aggregate high mask length

**%N**

> object name

**%m**

> object mask

**%i**

> inversed mask

**&#92;n**

> new line

**&#92;t**

> tabulation

Please note that no new lines inserted automatically after each sentence,
you have to add them into format string manually, elsewhere output will
be in one line (sometimes it makes sense):

	$ bgpq4 -6F "%n/%l; " as-eltel
	2001:1b00::/32; 2620:4f:8000::/48; 2a04:bac0::/29; 2a05:3a80::/48;

# NOTES ON SOURCES

By default *bgpq4* trusts data from all databases mirrored into NTT's IRR service.
Unfortunately, not all these databases are equal in how much can we trust their 
data.
RIR maintained databases (AFRINIC, ARIN, APNIC, LACNIC and RIPE)
shall be trusted more than the others because they have the knowledge about 
which address space is allocated to each ASN, other databases lack this 
knowledge and can (and actually do) contain some stale data: nobody but RIRs 
care to remove outdated route-objects when address space is revoked from one 
ASN and allocated to another. In order to keep their filters both compact and 
current, *bgpq4 users* are encouraged to use one of two method to limit 
database sources to only ones they trust.

One option is to use the '-S' flag. This limits all queries to a specific data 
source. For example, the following command tells IIRd to only use data from 
the RIPE RIR DB to build the prefix list for the AS-SET:

	$./bgpq4 -S RIPE AS-VOSTRON
	no ip prefix-list NN
	ip prefix-list NN permit 89.21.224.0/19
	ip prefix-list NN permit 134.0.64.0/21

Be aware though, than an AS-SET may contain members from other data sources.
In this case IRRd won't respond to the bgpq4 query will all the prefixes in the 
AS-SET tree. Make sure to use the '-S' flag with all the data sources required 
for the AS-SET being expanded:

	$./bgpq4 -S RIPE,ARIN AS-VOSTRON
	no ip prefix-list NN
	ip prefix-list NN permit 89.21.224.0/19
	ip prefix-list NN permit 134.0.64.0/21
	ip prefix-list NN permit 208.86.232.0/24
	ip prefix-list NN permit 208.86.233.0/24
	ip prefix-list NN permit 208.86.234.0/24
	ip prefix-list NN permit 208.86.235.0/24

The other option is to specify a source for an AS-SET or Route Set using the 
"::" notation. When bgpq4 detects this, it will look for "::" in the specified 
AS-SET or RS on the CLI, and in all members of the AS-SET/RS, and for each 
member with a data source specified in "::" format, it will set the IRRd data 
source to the given value, query the AS-SET/RS, then reset the data sources back
 to the default list for the next object in the tree.

	$./bgpq4 RIPE::AS-VOSTRON
	no ip prefix-list NN
	ip prefix-list NN permit 89.21.224.0/19
	ip prefix-list NN permit 134.0.64.0/21
	ip prefix-list NN permit 208.86.232.0/22
	ip prefix-list NN permit 208.86.232.0/24
	ip prefix-list NN permit 208.86.233.0/24
	ip prefix-list NN permit 208.86.234.0/24
	ip prefix-list NN permit 208.86.235.0/24

In comparison to the '-S' flag, this method return all the prefixes under the 
AS-SET, but the root of the tree "AS-VOSTRON" was queries from RIPE only. None 
of the member objects used the "::" notation so they were queries from the 
default source list (which is all sources).


General recommendations:

Use minimal set of RIR databases (only those in which you and your
customers have registered route-objects).

Avoid using ARIN-NONAUTH and RIPE-NONAUTH as trusted sources: these records
were created in database but for address space allocated to different RIR,
so the NONAUTH databases have no chance to confirm validity of this route
object.

	$ bgpq4 -S RIPE,RADB as-space
	no ip prefix-list NN
	ip prefix-list NN permit 195.190.32.0/19
	
	$ bgpq4 -S RADB,RIPE as-space
	no ip prefix-list NN
	ip prefix-list NN permit 45.4.4.0/22
	ip prefix-list NN permit 45.4.132.0/22
	ip prefix-list NN permit 45.6.128.0/22
	ip prefix-list NN permit 45.65.184.0/22
	[...]

When known, use the "::" notation to speicy the authortative data source for 
an AS-SET or RS instead of the -S flag.

# PERFORMANCE

To improve \`bgpq4\` performance when expanding extra-large AS-SETs you
shall tune OS settings to enlarge TCP send buffer.

FreeBSD can be tuned in the following way:

	sysctl -w net.inet.tcp.sendbuf_max=2097152

Linux can be tuned in the following way:

	sysctl -w net.ipv4.tcp_window_scaling=1

	sysctl -w net.core.rmem_max=2097152

	sysctl -w net.core.wmem_max=2097152

	sysctl -w net.ipv4.tcp_rmem="4096 87380 2097152"

	sysctl -w net.ipv4.tcp_wmem="4096 65536 2097152"

# BUILDING

This project uses autotools. If you are building from the repository,
run the following command to prepare the build system:

	./bootstrap

In order to compile the software, run:

	./configure

	make

	make install

If you wish to remove the generated build system files from your
working tree, run:

	make maintainer-clean

In order to create a distribution archive, run:

	make dist

# DIAGNOSTICS

When everything is OK,
**bgpq4**
generates access-list to standard output and exits with status == 0.
In case of errors they are printed to stderr and the program exits with
non-zero status.

# AUTHORS

Alexandre Snarskii, Christian David, Claudio Jeker, Job Snijders,
Massimiliano Stucchi, Michail Litvak, Peter Schoenmaker, Roelf Wichertjes,
and contributions from many others.

# SEE ALSO

**https://github.com/bgp/bgpq4**
BGPQ4 on Github.

**http://bgpfilterguide.nlnog.net/**
NLNOG's BGP Filter Guide.

**https://tcp0.com/cgi-bin/mailman/listinfo/bgpq4**
Users and interested parties can subscribe to the BGPQ4 mailing list bgpq4@tcp0.com

# PROJECT MAINTAINER

Job Snijders &lt;job@sobornost.net&gt;
