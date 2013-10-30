
include CONFIG
include VERSION

BUILDDIR=$(NAME)_$(VERSION)

do_subst = sed -e 's,__VERSION__,${VERSION},g' \
			-e 's,__PIDFILE__,$(PIDFILE),g' \
			-e 's,__DESTDIR__,$(DESTDIR),g' \
			-e 's,__DAEMONDIR__,$(DAEMONDIR),g' \
			-e 's,__CONFDIR__,$(CONFDIR),g' \
			-e 's,__PYTHON_LIB__,$(PYTHON_LIB),g' \
			-e 's,__LOGFILE__,$(LOGFILE),g' \

snompnpd:
	$(do_subst) < src/snompnpd.py > snompnpd
	$(do_subst) < src/setup.py.in > src/setup.py


init-script:
	if [ -f  src/utils/snompnpd.$(TARGET).init ];then\
        $(do_subst) < src/utils/snompnpd.$(TARGET).init > snompnpd.init;\
    else\
        echo "ERROR: No init script found for $(TARGET) target";\
    fi;
    # TODO:
    #else\
    #   $(do_subst) < src/utils/snompnod.lsb.init > $(BUILDDIR)/snompnpd.init;\
    #fi;

conf:
	$(do_subst) < src/snompnpd.conf-default > snompnpd.conf

clean: clean-tar
	find src/ -name "*.pyc" | xargs rm -fr
	rm -f snompnpd snompnpd.init snompnpd.conf
	rm -rf src/build
	rm -rf src/setup.py

build:
	cd src && python setup.py build --build-lib ./build/lib

install: clean snompnpd init-script conf build
	# install scripts
	install -d -m 0755 $(DAEMONDIR)
	install -d -m 0755 $(INITDIR)
	install -d -m 0755 $(PYTHON_LIB)
	install -d -m 0755 $(PYTHON_LIB)/snomprovisioning
	install -d -m 0750 $(CONFDIR)
	install -o $(USER) -g $(GROUP) -m 0755 snompnpd $(DAEMONDIR)/snompnpd
	install -o $(USER) -g $(GROUP) -m 0755 snompnpd.init $(INITDIR)/snompnpd
	install -o $(USER) -g $(GROUP) -m 0644 snompnpd.conf $(CONFDIR)/snompnpd.conf
	install -o $(USER) -g $(GROUP) -m 0644 src/build/lib/snomprovisioning/__init__.py $(PYTHON_LIB)/snomprovisioning/__init__.py
	install -o $(USER) -g $(GROUP) -m 0644 src/build/lib/snomprovisioning/sip.py $(PYTHON_LIB)/snomprovisioning/sip.py
	install -o $(USER) -g $(GROUP) -m 0644 src/build/lib/snomprovisioning/daemon.py $(PYTHON_LIB)/snomprovisioning/daemon.py

clean-tar:
	rm -rf ${BUILDDIR}

remove:
	rm -f $(DAEMONDIR)/snompnpd
	rm -f $(CONFDIR)/snompnpd.conf
	rm -r $(INITDIR)/snompnpd

tar: clean
	mkdir ${BUILDDIR}
	cp -a src ${BUILDDIR}/
	find ${BUILDDIR} -name .svn -type d | xargs rm -r
	cp COPYING LICENSE README.md TODO CONFIG VERSION INSTALL ${BUILDDIR}/
	cp Makefile ${BUILDDIR}/
	tar czvf ${BUILDDIR}.tgz ${BUILDDIR}
