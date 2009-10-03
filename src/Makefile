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


SOURCES = common.ml ipv6.ml parser.mly lexer.mll frontend.mli chain.ml frontend.mli \
	  frontend_types.ml ir.ml optimize.ml zone.ml \
	  frontend.ml ip6tables.ml rule.ml validate.ml parse.ml borderline.ml

LIBS    = unix str nums

RESULT  = main

USE_CAMLP4 = yes

OCAMLMAKEFILE = /usr/share/ocamlmakefile/OCamlMakefile

all: borderline
	./borderline ../configuration/main.bl



# Keep at the bottom.
include /usr/share/ocamlmakefile/OCamlMakefile


