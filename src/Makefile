OCAMLC=ocamlc -g
OCAMLOPT=ocamlopt
OCAMLDEP=ocamldep
INCLUDES=                 # all relevant -I options here
OCAMLFLAGS=$(INCLUDES)    # add other options for ocamlc here
OCAMLOPTFLAGS=$(INCLUDES) # add other options for ocamlopt here


-include .depend

parser.mli:
parser.ml: parser.mly lexer.ml
	ocamlyacc parser.mly

lexer.ml: parser.mli lexer.mll pt.ml
	ocamllex lexer.mll


.SUFFIXES: .ml .mli .cmo .cmi .cmx
%.cmp: %.ml
	$(OCAMLC) $(OCAMLFLAGS) -c $<

%.cmi: %.mli
	$(OCAMLC) $(OCAMLFLAGS) -c $<

%.cmx: %.ml
	$(OCAMLOPT) $(OCAMLOPTFLAGS) -c $<

SOURCES=$(wildcard *.mli *.ml *.mll *.mly)
.depend: parser.ml lexer.ml $(SOURCES)
	$(OCAMLDEP) $(INCLUDES) *.mli *.ml > .depend

clean:
        rm -f *.cm[iox]
        rm -f parser.ml
        rm -f parser.mli
        rm -f lexer.ml
        rm -f *~
        rm -f .depend

