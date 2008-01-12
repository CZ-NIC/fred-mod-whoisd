ACLOCAL_AMFLAGS = -I m4
CLEANFILES = ${IDL_ALL} .libs/libmodwhoisd *~ mod_whoisd.la

noinst_LTLIBRARIES = liborbwhoisd.la libmodwhoisd.la
noinst_DATA        = mod_whoisd.la
dist_pkgdata_DATA = conf/02-fred-mod-whoisd-apache.conf
EXTRA_DIST = unconfig.h fred-mod-whoisd.spec
BUILT_SOURCES = Whois.h Whois-common.c Whois-stubs.c

INCL = ${APACHE_CFLAGS} ${APACHE_CPPFLAGS} ${ORBIT_CFLAGS} ${CPPFLAGS} 
AM_LDFLAGS = ${ORBIT_LIBS} ${LIBS} ${LDFLAGS}

IDL_H   = @IDLPREFIX@.h
IDL_S   = @IDLPREFIX@-common.c @IDLPREFIX@-stubs.c
IDL_ALL = ${IDL_S} ${IDL_H}

liborbwhoisd_la_SOURCES = ${IDL_S} 
liborbwhoisd_la_CFLAGS  = ${ORBIT_CFLAGS} 
liborbwhoisd_la_LDFLAGS = ${ORBIT_LIBS}

libmodwhoisd_la_SOURCES = whois-client.c whois-client.h mod_whoisd.c 
libmodwhoisd_la_CFLAGS = ${INCL} -include ${IDL_H}
libmodwhoisd_la_LIBADD = liborbwhoisd.la

install-exec-local:
	mkdir -p ${DESTDIR}${APACHE_LIBEXECDIR}; \
	${APXS} -S LIBEXECDIR=${DESTDIR}${APACHE_LIBEXECDIR} -i -n 'mod_whoisd' mod_whoisd.la

uninstall-local:
	rm -rf ${DESTDIR}${APACHE_LIBEXECDIR}/mod_whoisd.so

mod_whoisd.la: libmodwhoisd.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${ORBIT_CFLAGS} ${AM_LDFLAGS}

${IDL_ALL}:
	${ORBIT_IDL} --noskels ${IDL}


