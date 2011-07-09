# Copyright 2009 Anders Fugmann.
# Distributed under the GNU General Public License v3
#
# This file is part of Borderline - A Firewall Generator
#
# Borderline is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# Borderline is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Borderline.  If not, see <http://www.gnu.org/licenses/>.


SOURCES = common.mli common.ml ipv6.mli ipv6.ml \
	  parser.mly lexer.mll frontend.mli chain.mli chain.ml \
	  frontend_types.ml ir.ml optimize.mli optimize.ml zone.mli zone.ml \
	  frontend.ml ip6tables.mli ip6tables.ml rule.mli rule.ml \
	  validate.ml parse.mli parse.ml borderline.ml

LIBS    = unix str nums

RESULT  = borderline

USE_CAMLP4 = yes

OCAMLMAKEFILE = /usr/share/ocamlmakefile/OCamlMakefile

OCAMLRUNPARAM=b
export OCAMLRUNPARAM=b

default: test

.PHONY: borderline borderline-native
borderline: dc

borderline-native: nc
	mv borderline borderline-native

borderline.ps: $(SOURCES)
	ocamlweb $^ --ps -o $@

.PHONY: web
web: borderline.ps

.PHONY: configure
configure: configure.ml
	ocamlc unix.cma $< -o $@

test: configure borderline
	./configure --force --output ../configuration/zones
	./borderline ../configuration/borderline.bl

.PHONY: %.sig
%.sig: %.ml
	@ocamlc -i $<

.PHONY: tests
tests: borderline
	@cd ../tests; ./test.sh

clean::
	$(RM) configure
	$(RM) *~

# Keep at the bottom.
-include $(OCAMLMAKEFILE)




