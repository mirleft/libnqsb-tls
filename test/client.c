#include "tls.h"
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

int config_client_context(struct tls* ctx) {

  struct tls_config *config = tls_config_new();

  if (tls_config_set_ciphers(config, "all") != 0) {
    perror("Error while setting ciphers\n");
    tls_config_free(config);
    return -1;
  }

  if (tls_config_set_ca_file(config, "./certificates/cert/certificate.pem") != 0) {
    perror("Error while ca\n");
    return -1;
  }

  tls_config_set_protocols(config, TLS_PROTOCOL_TLSv1_2);

  if (tls_configure(ctx, config) != 0) {
    perror("Error while running tls_configure\n");
    return -1;
  }

  return 0;
}

int client_loop(char *addr, char *port) {

  int sock;
  struct sockaddr_in s_addr;

  memset(&s_addr, 0, sizeof(s_addr));

  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  s_addr.sin_family = AF_INET;
  s_addr.sin_addr.s_addr = inet_addr(addr);
  s_addr.sin_port = htons(atoi(port));

  if (connect(sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
    perror("Error while running connect");
    return -1;
  }

  struct tls *ctx = tls_client();
  if (config_client_context(ctx) < 0)
    return -1;

  tls_connect_socket(ctx, sock, addr);

  int handshake_status = -2;
  while (handshake_status == -2 || handshake_status == -3) {
    handshake_status = tls_handshake(ctx);
  }

  return 0;

}

int main(int ac, char **av) {

  tls_init();

  return client_loop("127.0.0.1", "4433");
}
