#include <stdio.h>
#include <stdlib.h>


#include <bgpq3.h>

void sx_radix_node_freeall(struct sx_radix_node *n) {
  if (n->l != NULL) {
    sx_radix_node_freeall(n->l);
  }
  if (n->r != NULL) {
    sx_radix_node_freeall(n->r);
  }
  if (n->son != NULL) {
    sx_radix_node_freeall(n->son);
  }

  if (n->payload) {
    free(n->payload);
  }
  sx_prefix_destroy(n->prefix);
  free(n);
}

void sx_radix_tree_freeall(struct sx_radix_tree *t) {
  sx_radix_node_freeall(t->head);
  free(t);
}

void bgpq_prequest_freeall(struct bgpq_prequest *bpr) {

}

void expander_freeall(struct bgpq_expander *expander) {

  printf("starting to free all\n");
  // seg fault here
  // if (expander->sources != NULL) {
  //  printf("freeing soruces\n");
  //  free(expander->sources);
  //}
  //  if (expander->name != NULL) {
  //  printf("freeing name\n");
  //  free(expander->name);
  //}
    printf("freeing asn32s\n");
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
  printf("finished freeing all\n");
  
}

