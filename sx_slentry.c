
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "sx_slentry.h"

struct sx_slentry*
sx_slentry_new(char* t)
{
	struct sx_slentry* e = malloc(sizeof(struct sx_slentry));

	if (!e)
		return NULL;

	memset(e, 0, sizeof(struct sx_slentry));

	if (t)
		e->text = strdup(t);

	return e;
}

struct sx_tentry*
sx_tentry_new(char* t)
{
	struct sx_tentry* te = malloc(sizeof(struct sx_tentry));

	if (!te)
		return NULL;

	memset(te, 0, sizeof(struct sx_tentry));
	te->text = strdup(t);

	return te;
}
