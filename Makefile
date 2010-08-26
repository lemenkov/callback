install:
	install -D -p -m 0644 config.ini $(DESTDIR)/etc/sip-callback/config.ini
	install -D -p -m 0755 sip-callback.py $(DESTDIR)/usr/sbin/sip-callback
	install -D -p -m 0755 sip-callback.init $(DESTDIR)/etc/rc.d/init.d/sip-callback
	install -d $(DESTDIR)/var/run/sip-callback

clean:
	@rm -f *~
