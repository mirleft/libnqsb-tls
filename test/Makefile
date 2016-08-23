OCAML_LINK_FLAG = -L../_build
OCAML_COMPILE_FLAG = -I../_build/generated

LIBRESSL_LINK_FLAG = $(shell pkg-config --libs-only-L libtls)

all: server.ocaml-tls client.ocaml-tls server.libressl client.libressl

clean:
	rm client.o server.o server.opt client.opt

client.ocaml-tls: client.c
	$(CC) -o $@ $< -ltls $(OCAML_LINK_FLAG) $(OCAML_COMPILE_FLAG)

server.ocaml-tls: server.c
	$(CC) -o $@ $< -ltls $(OCAML_LINK_FLAG) $(OCAML_COMPILE_FLAG)

client.libressl: client.c
	$(CC) -o $@ $< -ltls $(LIBRESSL_LINK_FLAG) $(OCAML_COMPILE_FLAG)

server.libressl: server.c
	$(CC) -o $@ $< -ltls $(LIBRESSL_LINK_FLAG) $(OCAML_COMPILE_FLAG)


.PHONY: all clean
