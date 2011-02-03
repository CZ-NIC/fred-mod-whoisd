ACLOCAL_AMFLAGS = -I m4
include $(top_srcdir)/am_doxygen.am

testsdir=${LIBRARYDIR}/mod_whoisd/unittest
# testsdir=${prefix}/lib/mod_whoisd/unittest
CLEANFILES = ${IDL_ALL} .libs/libmodwhoisd *~ mod_whoisd.la conf/02-fred-mod-whoisd-apache.conf

noinst_LTLIBRARIES = liborbwhoisd.la libmodwhoisd.la
noinst_DATA        = mod_whoisd.la
dist_pkgdata_DATA = conf/02-fred-mod-whoisd-apache.conf
EXTRA_DIST = unconfig.h fred-mod-whoisd.spec doxy.conf
BUILT_SOURCES = ${IDL_C}

INCL = ${APACHE_CFLAGS} ${APACHE_CPPFLAGS} ${ORBIT_CFLAGS} ${CPPFLAGS} 
AM_LDFLAGS = ${ORBIT_LIBS} ${LIBS} ${LDFLAGS}

IDL_H   = @IDLPREFIX@.h
IDL_C   = @IDLPREFIX@-common.c
IDL_S   = @IDLPREFIX@-stubs.c
IDL_ALL = ${IDL_C} ${IDL_S} ${IDL_H}

nodist_liborbwhoisd_la_SOURCES = ${IDL_ALL} 
liborbwhoisd_la_CFLAGS  = ${ORBIT_CFLAGS} 
liborbwhoisd_la_LDFLAGS = ${ORBIT_LIBS}

libmodwhoisd_la_SOURCES = whois-client.c whois-client.h mod_whoisd.c 
libmodwhoisd_la_CFLAGS = ${INCL} -include ${IDL_H}
libmodwhoisd_la_LIBADD = liborbwhoisd.la

if DX_COND_html
doc_DATA = @DX_DOCDIR@/html/*
$(doc_DATA): doxygen-doc
MOSTLYCLEANFILES = ${DX_CLEANFILES}
endif

if WITH_UNITTESTS
tests_DATA 	  = unittests/*
endif


install-exec-local:
	mkdir -p ${DESTDIR}${APACHE_LIBEXECDIR}; \
	${APXS} -S LIBEXECDIR=${DESTDIR}${APACHE_LIBEXECDIR} -i -n 'mod_whoisd' mod_whoisd.la

uninstall-local:
	rm -rf ${DESTDIR}${APACHE_LIBEXECDIR}/mod_whoisd.so

mod_whoisd.la: libmodwhoisd.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${ORBIT_CFLAGS} ${AM_LDFLAGS}

${IDL_C}: ${IDL} ${IDLDIR}/Whois.idl ${IDLDIR}/Logger.idl \
 ${IDLDIR}/_dataTypes.idl ${IDLDIR}/Registry.idl \
 ${IDLDIR}/Filters.idl 
	${ORBIT_IDL} --noskels ${IDL}


