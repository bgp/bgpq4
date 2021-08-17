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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#include "sx_report.h"

static int reportStderr=1;

static char const* 
sx_report_name(sx_report_t t)
{ 
	switch (t) {
	case SX_MISFEATURE:
		return "MISSING FEATURE:";
	case SX_FATAL:
		return "FATAL ERROR:";
	case SX_ERROR:
		return "ERROR:";
	case SX_NOTICE:
		return "Notice:";
	case SX_DEBUG:
		return "Debug:";
	}

	return "...... HMMMMM.... ERROR... \n";
}

int
sx_report(sx_report_t t, char* fmt, ...)
{ 
	char buffer[65536];
	va_list ap;
	va_start(ap, fmt);

	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (reportStderr) { 
		fputs(sx_report_name(t), stderr);
		fputs(buffer, stderr);
	} else { 
		switch(t) { 
		case SX_FATAL: 
			syslog(LOG_ERR,"FATAL ERROR: %s", buffer);
			break;
		case SX_MISFEATURE:
		case SX_ERROR: 
			syslog(LOG_ERR,"ERROR: %s", buffer);
			break;
		case SX_NOTICE: 
			syslog(LOG_WARNING,"Notice: %s", buffer);
			break;
		case SX_DEBUG: 
			syslog(LOG_DEBUG,"Debug: %s", buffer);
			break;
		}
	}

	if (t == SX_FATAL)
		exit(-1);

	return 0;
}

int 
sx_debug(char const* const file, char const* const func, int const line, 
    char* fmt, ...)
{
	char buffer[65536];
	char bline[65536];

	va_list ap;
	va_start(ap, fmt);

	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	snprintf(bline, sizeof(bline), "DEBUG: %s:%i %s ", file, line, func);
	if (reportStderr) { 
		fputs(bline, stderr);
		fputs(buffer, stderr);
	} else { 
		syslog(LOG_DEBUG,"%s %s", bline, buffer);
	}

	return 0;
}

void
sx_openlog(char* progname)
{ 
	openlog(progname ? progname : "<unknown>", LOG_PID, LOG_DAEMON);
	reportStderr = 0;
}

