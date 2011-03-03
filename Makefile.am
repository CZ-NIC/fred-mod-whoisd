ACLOCAL_AMFLAGS = -I m4
include $(top_srcdir)/am_doxygen.am

testdatadir=${LIBRARYDIR}/mod_whoisd/unittest
# testdatadir=${prefix}/lib/mod_whoisd/unittest

CLEANFILES = .libs/libmodwhoisd *~ mod_whoisd.la \
    conf/02-fred-mod-whoisd-apache.conf \
    Admin.h Admin-common.c Admin-stubs.c \
    Filters.h Filters-common.c Filters-stubs.c \
    Whois.h Whois-common.c Whois-stubs.c \
    Logger.h Logger-common.c Logger-stubs.c \
    _dataTypes.h _dataTypes-common.c _dataTypes-stubs.c \
    Registry.h Registry-common.c Registry-stubs.c

noinst_LTLIBRARIES = libcorbadatatypes.la libcorbaregistry.la \
    libcorbawhois.la libcorbalogger.la \
    libcorbafilters.la libcorbaadmin.la libmodwhoisd.la

noinst_DATA        = mod_whoisd.la
dist_pkgdata_DATA = conf/02-fred-mod-whoisd-apache.conf
EXTRA_DIST = unconfig.h fred-mod-whoisd.spec doxy.conf
BUILT_SOURCES = _dataTypes-common.c Registry-common.c \
    Whois-common.c Logger-common.c Filters-common.c Admin-common.c

INCL = ${APACHE_CFLAGS} ${APACHE_CPPFLAGS} ${ORBIT_CFLAGS} ${CPPFLAGS} 
AM_LDFLAGS = ${ORBIT_LIBS} ${LIBS} ${LDFLAGS}

nodist_libcorbadatatypes_la_SOURCES = _dataTypes.h _dataTypes-common.c _dataTypes-stubs.c 
libcorbadatatypes_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbadatatypes_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbaregistry_la_SOURCES = Registry.h Registry-common.c Registry-stubs.c
libcorbaregistry_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbaregistry_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbaadmin_la_SOURCES = Admin-common.c Admin-stubs.c Admin.h 
libcorbaadmin_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbaadmin_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbafilters_la_SOURCES = Filters-common.c Filters-stubs.c Filters.h
libcorbafilters_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbafilters_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbawhois_la_SOURCES = Whois-common.c Whois-stubs.c Whois.h 
libcorbawhois_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbawhois_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbalogger_la_SOURCES = Logger-common.c Logger-stubs.c Logger.h
libcorbalogger_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbalogger_la_LDFLAGS = ${ORBIT_LIBS}

libmodwhoisd_la_SOURCES = whois-client.c whois-client.h mod_whoisd.c
libmodwhoisd_la_CFLAGS = ${INCL} -include Whois.h -include Logger.h \
    -include _dataTypes.h -include Registry.h -include Admin.h \
    -include Filters.h
libmodwhoisd_la_LIBADD = libcorbadatatypes.la libcorbaregistry.la \
    libcorbalogger.la libcorbawhois.la libcorbaadmin.la libcorbafilters.la

if DX_COND_html
doc_DATA = @DX_DOCDIR@/html/*
$(doc_DATA): doxygen-doc
MOSTLYCLEANFILES = ${DX_CLEANFILES}
endif

if WITH_UNITTESTS
dist_testdata_DATA = unittests/test_whois.py
endif

install-exec-local:
	mkdir -p ${DESTDIR}${APACHE_LIBEXECDIR}; \
	${APXS} -S LIBEXECDIR=${DESTDIR}${APACHE_LIBEXECDIR} -i -n 'mod_whoisd' mod_whoisd.la

uninstall-local:
	rm -rf ${DESTDIR}${APACHE_LIBEXECDIR}/mod_whoisd.so

mod_whoisd.la: libmodwhoisd.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${ORBIT_CFLAGS} ${AM_LDFLAGS}

_dataTypes-common.c : $(IDLDIR)/_dataTypes.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/_dataTypes.idl

Registry-common.c : $(IDLDIR)/Registry.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Registry.idl

Whois-common.c : $(IDLDIR)/Whois.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Whois.idl

Logger-common.c : $(IDLDIR)/Logger.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Logger.idl

Admin-common.c : $(IDLDIR)/Admin.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Admin.idl

Filters-common.c : $(IDLDIR)/Filters.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Filters.idl
