#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sx_report.h"

#ifndef SX_MAXSOCKBUF_MAX
#define SX_MAXSOCKBUF_MAX (2*1024*1024)
#endif

int
sx_maxsockbuf(int s, int dir)
{ 
	int optval = 0, voptval;
	int hiconf = -1, loconf = -1;
	unsigned int voptlen;
	int phase = 0, iterations = 0;

	if (s<0) { 
		sx_report(SX_FATAL,"Unable to maximize sockbuf on invalid "
		    "socket %i\n", s);
		exit(1);
	}

	voptlen = sizeof(optval);

	if (getsockopt(s, SOL_SOCKET, dir, (void*)&optval, &voptlen) == -1) {
		sx_report(SX_ERROR,"initial getsockopt failed: %s\n",
		    strerror(errno));
		return -1;
	}

	for (;;) { 
		iterations++;

		if (phase == 0)
			optval<<=1; 
		else { 
			if (optval == (hiconf + loconf) / 2)
				break;
			optval = (hiconf + loconf) / 2;
		}

		if (optval > SX_MAXSOCKBUF_MAX && phase == 0) 
			break;

		if (setsockopt(s, SOL_SOCKET, dir, (void*)&optval,
		    sizeof(optval)) == -1) {

			if (phase == 0)
				phase = 1; 

			hiconf = optval; 

			continue;
		} else { 
			loconf = optval;
		}

		voptlen = sizeof(voptval);

		if (getsockopt(s, SOL_SOCKET, dir, (void*)&voptval,
		    &voptlen) == -1) {
			sx_report(SX_ERROR,"getsockopt failed: %s\n",
			    strerror(errno));
			return -1;
		} else if (voptval < optval) { 
			if (phase == 0) { 
				phase = 1;
				optval >>= 1;
				continue;
			} else if (phase == 1) { 
				phase = 2;
				optval -= 2048;
				continue;
			} else
				break;
		} else if (voptval >= SX_MAXSOCKBUF_MAX) { 
			/*
			 * ... and getsockopt not failed and voptval>=optval.
			 * Do not allow to increase sockbuf too much even in
			 * case OS permits it
			 */
			break;
		}
	}

	voptlen = sizeof(voptval);
	if (getsockopt(s, SOL_SOCKET, dir, (void*)&voptval,
	    &voptlen) == -1) {
		sx_report(SX_ERROR,"getsockopt(final stage) failed: %s\n", 
		    strerror(errno));
		return -1;
	} else { 
		/*
		printf("Finally got %i bytes of recvspace in %i interations\n", 
			voptval, iterations);
		*/
	}

	return voptval;
}
