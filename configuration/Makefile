.DEFAULT_GOAL := autogenerated

DESTDIR ?= .

CP = cp

AUTOGENERATED = generic/services.bl generic/allocated6.bl generic/bogon6.bl generic/bogon4.bl generic/l4proto.bl generic/states.bl

.PHONY: autogenerated install
autogenerated: $(AUTOGENERATED)
$(AUTOGENERATED): Makefile

.DELETE_ON_ERROR: generic/services.bl
generic/services.bl: /etc/services
	@echo "Gen     :" $@
	@egrep -v "^#" $< | while read name number rest; do \
          if [ "$${number##*/}" = "tcp" -o "$${number##*/}" = "udp" ]; then \
	    for n in $${name}; do \
              echo "define \"$${n}\" += [ $${number%%/*} ]"; \
            done; \
          fi; \
        done | sort -u > $@

generic/allocated6.xml: URL = http://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml
generic/allocated6.xml:
	@echo "Gen     :" $@
	@curl -s $(URL) > $@

.DELETE_ON_ERROR: generic/allocated6.bl
generic/allocated6.bl: generic/allocated6.xml allocations.xslt
	@echo "Gen     :" $@
	@echo "# Extracted from $(URL)" > $@
	@echo -n "define \"allocated6\" = [ " >> $@
	@xsltproc allocations.xslt generic/allocated6.xml >> $@
	@echo -n " ]" >> $@

.DELETE_ON_ERROR: generic/bogon6.bl
generic/bogon6.bl: URL = https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt
generic/bogon6.bl:
	@echo "Gen     :" $@
	@echo "# Extracted from $(URL)" > $@
	@echo -n "define \"bogon6\" = [ " >> $@
	@curl -s $(URL) | grep -v "^#" | sed 's/$$/,/g' >> $@
	@echo -n " ]" >> $@

.DELETE_ON_ERROR: generic/bogon4.bl
generic/bogon4.bl: URL = https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
generic/bogon4.bl:
	@echo "Gen     :" $@
	@echo "# Extracted from $(URL)" > $@
	@echo -n "define \"bogon4\" = [ " >> $@
	@curl -s $(URL) | grep -v "^#" | sed 's/$$/,/g' >> $@
	@echo -n " ]" >> $@

generic/l4proto.bl: force
	@echo "Gen     :" $@
	@echo "# Extracted from 'nft describe meta l4proto'" > $@
	@/usr/sbin/nft describe meta l4proto | \
          tail -n +2 | \
          while read name id; do \
            echo "define $${name} = $${id}"; # $${id}\
          done >> $@

generic/states.bl: force
	@echo "Gen     :" $@
	@echo "# Extracted from 'nft describe ct state'" > $@
	@/usr/sbin/nft describe ct state | \
          tail -n +4 | \
          while read name id; do \
            echo "define $${name} = \"$${name}\""; \
          done >> $@

clean:
	@find . -name \*~ | xargs $(RM)
	@$(RM) $(AUTOGENERATED)

install: autogenerated
	[ -d $(DESTDIR)/etc/borderline/zones/ ] || mkdir -p $(DESTDIR)/etc/borderline/zones/
	[ -d $(DESTDIR)/etc/borderline/generic/ ] || mkdir -p $(DESTDIR)/etc/borderline/generic/
	$(CP) *.bl $(DESTDIR)/etc/borderline
	$(CP) -av zones/*.bl $(DESTDIR)/etc/borderline/zones/
	$(CP) -av generic/*.bl $(DESTDIR)/etc/borderline/generic/

.PHONY: force
force:
