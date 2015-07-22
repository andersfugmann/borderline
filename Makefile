.PHONY: build force
build:
force:

clean install unittest build tests: %: force
	omake -w $@ -j 4
