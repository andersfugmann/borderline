.DEFAULT_GOAL := build

install: release
	mkdir -p $(DESTDIR)/etc/default/
	mkdir -p $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)/usr/sbin/
	make -C configuration install
	cp _build/default/bin/borderline.exe $(DESTDIR)/usr/sbin/borderline
	cp _build/default/bin/bl_configure.exe $(DESTDIR)/usr/sbin/bl_configure


.PHONY: unittest
unittest: build
	dune exec bin/unit_test.exe

.PHONY: test
test: build unittest
	cd tests; BORDERLINE="../_build/default/bin/borderline.exe" ./test.sh

.PHONY: integration
integration:
	make -C configuration
	#$(RM) configuration/zones/wlan* configuration/zones/eth* configuration/zones/ext*
	#_build/bl_configure.opt --output configuration/zones --force
	echo "#!/usr/sbin/nft -f" > test.nft
	echo "flush ruleset" >> test.nft
	dune exec bin/borderline.exe -- configuration/borderline.bl >> test.nft
	sed -i 's/ifgroup/ifname/g' test.nft
	sed -i 's/if[ ]* {/ifname {/g' test.nft
	sudo /usr/sbin/nft -c -o -n -f test.nft
	tail -n4 test.nft

.PHONY: build
build:
	dune build

.PHONY: release
release:
	dune build -p borderline

.PHONY: clean
clean:
	dune clean

.PHONY:deb
deb:
	dpkg-buildpackage --no-sign --build=binary -nc

.PHONY:debian
debian:
	gbp dch --ignore-branch --release --full -a --spawn-editor=snapshot -a --git-author
	dpkg-buildpackage -b -uc


force:
