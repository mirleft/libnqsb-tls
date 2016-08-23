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

int config_server_context(struct tls *srv_ctx) {

  struct tls_config *config = tls_config_new();

  if (tls_config_set_ciphers(config, "all") != 0) {
    perror("Error while setting ciphers");
    tls_config_free(config);
    return -1;
  }

  if (tls_config_set_cert_file(config, "./certificates/cert/certificate.pem") != 0) {
    perror("Error while setting ciphers");
    tls_config_free(config);
    return -1;
  }

  if (tls_config_set_key_file(config, "./certificates/csr/key.pem") != 0) {
    perror("Error while setting key file");
    tls_config_free(config);
    return -1;
  }

  tls_config_set_protocols(config, TLS_PROTOCOL_TLSv1_2);

  if (tls_configure(srv_ctx, config) != 0) {
    perror("Error while configuring server context");
    perror(tls_error(srv_ctx));
    tls_config_free(config);
    return -1;
  }

  tls_config_free(config);
  return 0;
}

int server_loop(char *addr, char *port) {
  int sock;
  int clt_fd;
  struct sockaddr_in srv_addr;
  struct sockaddr_in clt_addr;
  unsigned int clt_len = sizeof(clt_addr);
  int enable = 1;

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Error while configuring socket");
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    return -1;

  memset(&srv_addr, 0, sizeof(srv_addr));

  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = inet_addr(addr);
  srv_addr.sin_port = htons(atoi(port));

  if (bind(sock, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) < 0) {
    perror("Bind error");
    return -1;
  }

  if (listen(sock, 1024) < 0) {
    perror("Error while listen()");
    return -1;
  }

  if ((clt_fd = accept(sock, (struct sockaddr *) &clt_addr, &clt_len)) < 0) {
    perror("Error while accept");
    return -1;
  }

  struct tls *srv_ctx = tls_server();
  struct tls *srv_cctx;

  if (config_server_context(srv_ctx) != 0)
    return -1;

  if (tls_accept_socket(srv_ctx, &srv_cctx, clt_fd) != 0) {
    perror("Error while running tls_accept_socket()");
    return -1;
  }

  int handshake_status = -2;
  while (handshake_status == -2 || handshake_status == -3) {
    handshake_status = tls_handshake(srv_cctx);
  }

  tls_close(srv_cctx);
  tls_free(srv_cctx);
  tls_free(srv_ctx);
  close(clt_fd);

  return 0;
}

int main(int ac, char **av) {

  tls_init();
  return server_loop("127.0.0.1", "4433");
}
