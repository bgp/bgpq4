#ifndef SX_SLENTRY_H_
#define SX_SLENTRY_H_

#if HAVE_SYS_QUEUE_H && HAVE_STAILQ_IN_SYS_QUEUE
#include <sys/queue.h>
#else
#include "sys_queue.h"
#endif

#if HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <sys/tree.h>
#endif

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
