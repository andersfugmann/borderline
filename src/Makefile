# FCS - Firewall compiler suite
# Copyright Anders Fugmann
#

OCAMLC=ocamlc -g
OCAMLOPT=ocamlopt
OCAMLLEX=ocamllex
OCAMLDEP=ocamldep
OCAMLYACC=ocamlyacc
OCAMLFLAGS=$(INCLUDES)    # add other options for ocamlc here
OCAMLOPTFLAGS=$(INCLUDES) # add other options for ocamlopt here
OCAMLBUILD=ocamlbuild

.PHONY: main
.PHONY: FORCE

FORCE:

%.byte: FORCE 
	$(OCAMLBUILD) $@

main: main.byte
	ln -fs main.byte main

.PHONY: clean
clean:
	@$(RM) -f main.native main
	@$(RM) -fr _build


