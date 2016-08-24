#include "tls.h"
#include "args.h"
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int config_client_context(struct tls* ctx, struct args_s* args) {

  struct tls_config *config = tls_config_new();

  if (tls_config_set_ciphers(config, args->ciphersuite) != 0) {
    perror("Error while setting ciphers\n");
    tls_config_free(config);
    return -1;
  }

  if (tls_config_set_ca_file(config, "./certificates/cert/certificate.pem") != 0) {
    perror("Error while ca\n");
    return -1;
  }

  tls_config_set_protocols(config, TLS_PROTOCOL_TLSv1_2);

  if (args->verify_cert == 0) {
    tls_config_insecure_noverifycert(config);
    tls_config_insecure_noverifyname(config);
  }

  if (tls_configure(ctx, config) != 0) {
    perror("Error while running tls_configure\n");
    return -1;
  }

  return 0;
}

int client_loop(struct args_s* args) {

  int sock;
  struct sockaddr_in s_addr;

  memset(&s_addr, 0, sizeof(s_addr));

  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  s_addr.sin_family = AF_INET;
  s_addr.sin_addr.s_addr = inet_addr(args->addr);
  s_addr.sin_port = htons(atoi(args->port));

  if (connect(sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
    perror("Error while running connect");
    return -1;
  }

  struct tls *ctx = tls_client();
  if (config_client_context(ctx, args) < 0)
    return -1;

    tls_connect_socket(ctx, sock, args->addr);
  int handshake_status = -2;
  while (handshake_status == -2 || handshake_status == -3) {
    handshake_status = tls_handshake(ctx);
  }

  return 0;

}

int main(int ac, char **av) {
  struct args_s *args;
  int exit_val = 0;
  if ((args = parse_args(ac, av)) == NULL)
    return -1;
  tls_init();

  exit_val = client_loop(args);
  free(args);
  return exit_val;
}
