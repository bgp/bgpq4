/*
 * Copyright (c) 2019-2020 Job Snijders <job@sobornost.net>
 * Copyright (c) 2018 Peter Schoenmaker <pds@ntt.net>
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
#include <stdio.h>
#include <stdlib.h>

#include "extern.h"

void
sx_radix_node_freeall(struct sx_radix_node *n) {

	if (n->l != NULL)
		sx_radix_node_freeall(n->l);

	if (n->r != NULL)
		sx_radix_node_freeall(n->r);

	if (n->son != NULL)
		sx_radix_node_freeall(n->son);

	if (n->payload)
		free(n->payload);

	sx_prefix_destroy(n->prefix);

	free(n);
}

void
sx_radix_tree_freeall(struct sx_radix_tree *t) {

	if (t->head != NULL)
		sx_radix_node_freeall(t->head);

	free(t);
}

void
bgpq_prequest_freeall(struct bgpq_prequest *bpr) {
}

void
expander_freeall(struct bgpq_expander *expander) {

	// printf("starting to free all\n");
	// seg fault here
	// if (expander->sources != NULL) {
	//  printf("freeing soruces\n");
	//  free(expander->sources);
	//}
	//  if (expander->name != NULL) {
	//  printf("freeing name\n");
	//  free(expander->name);
	//}
	// printf("freeing asn32s\n");

	for (int i = 0; i < 65536; i++) {
		if (expander->asn32s[i] != NULL) {
			free(expander->asn32s[i]);
		}
	}

	// if (expander->match != NULL) {
	// printf("freeing match\n");
	//  free(expander->match);
	//}
	//if (expander->server != NULL) {
	//  printf("freeing server\n");
	//  free(expander->server);
	//}
	//if (expander->port != NULL) {
	//   printf("freeing port\n");
	//   free(expander->port);
	//}
	//if (expander->format != NULL) {
	//  printf("freeing format\n");
	//  free(expander->format);
	//}

	sx_radix_tree_freeall(expander->tree);

	bgpq_prequest_freeall(expander->firstpipe);
	bgpq_prequest_freeall(expander->lastpipe);

	// printf("finished freeing all\n");
}
