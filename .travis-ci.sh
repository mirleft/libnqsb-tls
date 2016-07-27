wget https://raw.githubusercontent.com/ocaml/ocaml-travisci-skeleton/master/.travis-ocaml.sh
sh .travis-ocaml.sh

eval `opam config env`

opam pin add --yes -n $(pwd)
opam install --yes depext
OPAMYES=1 opam depext libnqsb-tls
opam install --deps-only --yes libnqsb-tls
opam install --yes --verbose libnqsb-tls
