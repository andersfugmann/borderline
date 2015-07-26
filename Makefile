.PHONY: build force
build:
force:

clean install unittest build tests test: %: force
	omake -w $@ -j 4
