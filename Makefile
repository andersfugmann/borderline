.PHONY: deb debian %

.DEFAULT_GOAL := build

debian:
	dpkg-buildpackage -b -uc

dep:
	opam install omake
	omake dep

%:
	omake -w $@ -j 4
