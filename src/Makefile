# FCS - Firewall compiler suite
# Copyright Anders Fugmann
#

OCAMLBUILD=ocamlbuild -cflags -g -lflag -g -quiet -lflag unix.cma -lflag str.cma

.PHONY: main
.PHONY: force

test_run: main
	OCAMLRUNPARAM=b ./main

all: main

force:

%.byte: force
	$(OCAMLBUILD) $@

main: main.byte
	@ln -fs main.byte main

.PHONY: clean
clean:
	@$(RM) -f main.native main
	@$(RM) -fr _build
	@$(RM) -f *~



