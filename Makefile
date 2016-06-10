BUILDDIR=_build
VPATH=$(BUILDDIR)
OCAMLDIR=$(shell ocamlopt -where)
$(shell mkdir -p $(BUILDDIR) $(BUILDDIR)/stub $(BUILDDIR)/lib $(BUILDDIR)/stub_generator $(BUILDDIR)/echo_client $(BUILDDIR)/generated)
PACKAGES=ipaddr,rresult,tls,ctypes.stubs,ctypes.foreign,nocrypto.unix,memcpy
OCAMLDEP=ocamldep

# The files used to build the stub generator.
BINDING_FILES = $(BUILDDIR)/lib/nqsb.cmx           \
		$(BUILDDIR)/lib/nqsb_x509.cmx      \
		$(BUILDDIR)/lib/nqsb_peer.cmx      \
		$(BUILDDIR)/lib/nqsb_unix.cmx      \
		$(BUILDDIR)/lib/nqsb_config.cmx

GENERATOR_FILES= $(BINDING_FILES) \
		 $(BUILDDIR)/lib/bindings.cmx		\
		 $(BUILDDIR)/stub_generator/generate.cmx

# The files from which we'll build a shared library.
LIBFILES=$(BUILDDIR)/lib/nqsb.cmx			\
	 $(BUILDDIR)/lib/nqsb_x509.cmx			\
	 $(BUILDDIR)/lib/nqsb_peer.cmx			\
	 $(BUILDDIR)/lib/nqsb_unix.cmx			\
	 $(BUILDDIR)/lib/nqsb_config.cmx		\
         $(BUILDDIR)/lib/bindings.cmx			\
	 $(BUILDDIR)/generated/tls_bindings.cmx		\
         $(BUILDDIR)/lib/apply_bindings.cmx		\
         $(BUILDDIR)/generated/tls.o

CAML_INIT=$(BUILDDIR)/stub/init.o

# The files that we'll generate
GENERATED=$(BUILDDIR)/generated/tls.h \
          $(BUILDDIR)/generated/tls.c \
          $(BUILDDIR)/generated/tls_bindings.ml


OSTYPE:=$(shell ocamlfind ocamlc -config | awk '/^os_type:/ {print $$2}')
SYSTEM:=$(shell ocamlfind ocamlc -config | awk '/^system:/ {print $$2}')
EXTDLL:=$(shell ocamlfind ocamlc -config | awk '/^ext_dll:/ {print $$2}')
CC:= $(shell ocamlfind ocamlc -config | awk '/^bytecomp_c_compiler/ {for(i=2;i<=NF;i++) printf "%s " ,$$i}')

ifeq ($(OSTYPE),$(filter $(OSTYPE),Win32 Cygwin))
EXTEXE=.exe
else
EXTEXE=
endif

GENERATOR=$(BUILDDIR)/generate$(EXTEXE)

all: sharedlib

sharedlib: $(BUILDDIR)/libtls$(EXTDLL)


ifeq ($(OSTYPE),$(filter $(OSTYPE),Win32 Cygwin))
$(BUILDDIR)/libtls$(EXTDLL): $(CAML_INIT) $(LIBFILES)
	ocamlfind opt -o $@ -linkpkg -output-obj -verbose -package $(PACKAGES) $^
else ifeq ($(SYSTEM),$(filter $(SYSTEM),macosx))
$(BUILDDIR)/libtls$(EXTDLL): $(CAML_INIT) $(LIBFILES)
	ocamlfind opt -o $@ -linkpkg -runtime-variant _pic -verbose -ccopt -dynamiclib -package $(PACKAGES) $^
else
$(BUILDDIR)/libtls$(EXTDLL): $(CAML_INIT) $(LIBFILES)
	ocamlfind opt -o $@ -linkpkg -output-obj -runtime-variant _pic -verbose -package $(PACKAGES) $^
endif

stubs: $(GENERATED)

$(BUILDDIR)/lib/nqsb_config.cmx : $(BUILDDIR)/lib/nqsb_config.cmi
$(BUILDDIR)/lib/nqsb_unix.cmx : $(BUILDDIR)/lib/nqsb_unix.cmi
$(BUILDDIR)/lib/nqsb_peer.cmx : $(BUILDDIR)/lib/nqsb_peer.cmi
$(BUILDDIR)/lib/nqsb.cmx : $(BUILDDIR)/lib/nqsb.cmi

$(BUILDDIR)/stub/%.o:
	ocamlc -g -c stub/init.c
	mv init.o $@

$(GENERATED): $(GENERATOR)
	$(GENERATOR) $(BUILDDIR)/generated

$(BUILDDIR)/%.o: %.c
	$(CC) -c -o $@ -fPIC -I $(shell ocamlfind query ctypes) -I $(OCAMLDIR) -I $(OCAMLDIR)/../ctypes $<

$(BUILDDIR)/%.cmx: %.ml
	ocamlfind opt -c -o $@ -I $(BUILDDIR)/generated -I $(BUILDDIR)/lib -package $(PACKAGES) $<

$(BUILDDIR)/%.cmi: %.mli
	ocamlfind c -c -o $@ -I $(BUILDDIR)/generated -I $(BUILDDIR)/lib -package $(PACKAGES) $<

$(GENERATOR): $(GENERATOR_FILES)
	ocamlfind opt -o $@ -linkpkg -package $(PACKAGES) $^

clean:
	rm -rf $(BUILDDIR)
