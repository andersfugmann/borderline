.PHONY: %

.DEFAULT_GOAL := build

dep:
	opam install omake
	omake dep

#oUnit batteries menhir omake

%:
	omake -w $@ -j 4
