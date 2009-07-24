# FCS - Firewall compiler suite
# Copyright Anders Fugmann
#

OCAMLBUILD=ocamlbuild -verbose 1 -cflags -g -lflag -g -quiet -lflag unix.cma -lflag str.cma -lflag nums.cma

.PHONY: main
.PHONY: force

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



