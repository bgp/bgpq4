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

#ifndef SX_REPORT_H_
#define SX_REPORT_H_

typedef enum { 
	SX_DEBUG = 0,
	SX_NOTICE,
	SX_ERROR,
	SX_MISFEATURE,
	SX_FATAL
} sx_report_t;

/* opens syslog and disables logging to stderr */
void sx_openlog(char* progname);

int  sx_report(sx_report_t, char* fmt, ...) 
	__attribute__ ((format (printf, 2, 3)));

int sx_debug(char const* const, char const* const, int const, char* fmt, ...)
	__attribute__ ((format (printf, 4, 5)));

#define SX_DEBUG(a,b,c...) if(a) sx_debug(__FILE__,__FUNCTION__,__LINE__,\
	b, ## c);

#endif
