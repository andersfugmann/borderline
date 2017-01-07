.PHONY: %

.DEFAULT_GOAL := build

dep:
	opam install omake
	omake dep

%:
	omake -w $@ -j 4
