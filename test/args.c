#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

struct args_s {
  char *port;
  char *addr;
  int verify_cert;
  int mesure_handshake;
  char *file;
  char *ciphersuite;
};

struct args_s *parse_args(int ac, char **av) {
  struct args_s* args = malloc(sizeof(struct args_s));
  args->verify_cert = 0;
  args->mesure_handshake = 0;
  args->file = NULL;
  args->ciphersuite = "default";
  args->port = NULL;
  args->addr = NULL;
  int c;

  while ((c = getopt(ac, av, "vhf:c:p:a:")) != -1) {
    switch (c) {
    case 'v':
      args->verify_cert = 1;
      break;
    case 'h':
      args->mesure_handshake = 1;
      break;
    case 'f':
      args->file = optarg;
      break;
    case 'p':
      args->port = optarg;
      break;
    case 'a':
      args->addr = optarg;
      break;
    case 'c':
      args->ciphersuite = optarg;
      break;
    default :
      perror("Invalid arguments");
      return NULL;
    }
  }
  if ((args->port == NULL) || (args->addr == NULL)) {
    perror("Missing port (-p) and addr (-a) arguments");
    return NULL;
  }
  return args;
}
