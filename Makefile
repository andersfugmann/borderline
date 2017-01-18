.PHONY: deb debian %

.DEFAULT_GOAL := build

debian:
	gbp dch --ignore-branch --release --full -a --spawn-editor=snapshot -a --git-author
	dpkg-buildpackage -b -uc

dep:
	opam install omake
	omake dep

%:
	omake -w $@ -j 4
