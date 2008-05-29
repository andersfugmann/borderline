# FCS - Firewall compiler suite
# Copyright Anders Fugmann
#

OCAMLC=ocamlc -g
OCAMLOPT=ocamlopt
OCAMLDEP=ocamldep
INCLUDES=                 # all relevant -I options here
OCAMLFLAGS=$(INCLUDES)    # add other options for ocamlc here
OCAMLOPTFLAGS=$(INCLUDES) # add other options for ocamlopt here

.SUFFIXES: .ml .mli .cmo .cmi .cmx .mll .mly

#-include .depend

types: types.cmo
	$(OCAMLC) -o $@ $<

parser.mli parser.ml: parser.mly lexer.ml
	ocamlyacc parser.mly

lexer.ml: lexer.mll
	ocamllex lexer.mll

%.cmo: %.ml
	$(OCAMLC) $(OCAMLFLAGS) -c $<

%.cmi: %.mli
	$(OCAMLC) $(OCAMLFLAGS) -c $<

%.cmx: %.ml
	$(OCAMLOPT) $(OCAMLOPTFLAGS) -c $<

SOURCES=$(wildcard *.mli *.ml *.mll *.mly)
.depend: parser.ml lexer.ml $(SOURCES)
	$(OCAMLDEP) $(INCLUDES) *.mli *.ml > .depend

clean:
	@rm -f *.cm[iox]
	@rm -f parser.ml
	@rm -f parser.mli
	@rm -f lexer.ml
	@rm -f *~
	@rm -f .depend

