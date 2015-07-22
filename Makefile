.PHONY: build all install

install: bin/borderline bin/unit_test bin/bl_configure

build:
	omake -w

_build/%.opt: build

bin/%: _build/%.opt
	mkdir -p bin
	cp $< $@


test: bin/unit_test
	bin/unit_test

clean:
	$(RM) -f _build
	$(RM) -f bin
