#ifndef SX_SLENTRY_H_
#define SX_SLENTRY_H_

#include <sys/queue.h>
#include <sys/tree.h>

struct sx_slentry {
	STAILQ_ENTRY(sx_slentry) next;
	char*  text;
};

struct sx_slentry* sx_slentry_new(char* text);

struct sx_tentry {
	RB_ENTRY(sx_tentry) entry;
	char* text;
};

struct sx_tentry* sx_tentry_new(char* text);

#endif
