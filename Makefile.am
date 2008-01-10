ACLOCAL_AMFLAGS = -I ${top_srcdir}/m4/
CLEANFILES = ${IDL_ALL} .libs/libmodwhoisd *~

noinst_LTLIBRARIES = liborbwhoisd.la libmodwhoisd.la
noinst_DATA        = mod_whoisd.la

INCLUDES   = ${APACHE_CFLAGS} ${APACHE_CPPFLAGS} ${ORBIT_CFLAGS} ${CPPFLAGS} 
AM_LDFLAGS = ${ORBIT_LIBS} ${LIBS} ${LDFLAGS}

IDL_H   = @IDLPREFIX@.h
IDL_S   = @IDLPREFIX@-common.c @IDLPREFIX@-stubs.c
IDL_ALL = ${IDL_S} ${IDL_H}

liborbwhoisd_la_SOURCES = ${IDL_S} 
liborbwhoisd_la_CFLAGS  = ${ORBIT_CFLAGS} 
liborbwhoisd_la_LDFLAGS = ${ORBIT_LIBS}

libmodwhoisd_la_SOURCES = whois-client.c mod_whoisd.c 
libmodwhoisd_la_CFLAGS = ${INCLUDES} -include ${IDL_H}
libmodwhoisd_la_LIBADD = liborbwhoisd.la

install-exec-local:
	${APXS} -i -n 'mod_whoisd' mod_whoisd.la

mod_whoisd.la: libmodwhoisd.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${ORBIT_CFLAGS} ${AM_LDFLAGS}

${IDL_ALL}:
	${ORBIT_IDL} --noskels ${IDL}


