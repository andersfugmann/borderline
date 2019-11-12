.PHONY: deb debian force

.DEFAULT_GOAL := build

debian:
	gbp dch --ignore-branch --release --full -a --spawn-editor=snapshot -a --git-author
	dpkg-buildpackage -b -uc

install: build
	mkdir -p $(DESTDIR)/etc/default/
	mkdir -p $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)/usr/sbin/
	make -C configuration install
	$(CP) _build/default/bin/borderline.exe $(DESTDIR)/usr/sbin/borderline
	$(CP) _build/default/bin/bl_configure.exe $(DESTDIR)/usr/sbin/bl_configure

unittest:
	dune exec bin/unit_test.exe

.PHONY: tests
tests: build
	cd tests; BORDERLINE="../_build/default/bin/borderline.exe" ./test.sh

test: build
	make -C configuration
	#$(RM) configuration/zones/wlan* configuration/zones/eth* configuration/zones/ext*
	#_build/bl_configure.opt --output configuration/zones --force
	echo "#!/usr/sbin/nft -f" > test.nft
	echo "flush ruleset" >> test.nft
	dune exec bin/borderline.exe -- configuration/borderline.bl | tee -a test.nft

build:
	dune build

force:

clean:
	dune clean
