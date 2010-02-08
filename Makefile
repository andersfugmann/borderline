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

CP=cp

.PHONY: autogen install

default: borderline autogen bl-configure
	@echo "Now do a 'sudo make install'"

autogen:
	$(MAKE) -C configuration autogenerated

borderline:
	$(MAKE) -C src borderline-native
	$(CP) -L src/borderline-native borderline

bl-configure:
	$(MAKE) -C src configure
	$(CP) -L src/configure bl-configure

/etc/default/borderline:
	echo "MAIN=/etc/borderline/borderline.bl" > $@

install: borderline bl-configure autogen /etc/default/borderline

	mkdir -p /etc/borderline /etc/borderline/zones /etc/borderline/generic
	$(CP) borderline /usr/local/sbin/
	$(CP) bl-configure /usr/local/sbin/
	$(CP) borderline.sh /etc/init.d/
	$(CP) configuration/*.bl /etc/borderline
	$(CP) -av configuration/zones/*.bl /etc/borderline/zones/
	$(CP) -av configuration/generic/*.bl /etc/borderline/generic/

clean::
	$(RM) -f borderline
	$(RM) -fr *~

clean::
	$(MAKE) -C configuration clean
	$(MAKE) -C src clean
