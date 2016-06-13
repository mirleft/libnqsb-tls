wget https://raw.githubusercontent.com/ocaml/ocaml-travisci-skeleton/master/.travis-ocaml.sh
sh .travis-ocaml.sh

eval `opam config env`

opam pin add --yes -n $(pwd)
opam install --yes depext
opam depext libnqsb-tls
opam install --deps-only --yes libnqsb-tls
opam install --build-test --yes --verbose libnqsb-tls
