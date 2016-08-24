struct args_s {
  char *port;
  char *addr;
  int verify_cert;
  int mesure_handshake;
  char *file;
  char *ciphersuite;
};

struct args_s *parse_args(int ac, char **av);
