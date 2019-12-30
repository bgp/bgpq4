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

