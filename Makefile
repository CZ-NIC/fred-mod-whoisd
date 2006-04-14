APXS	= apxs2
APR-CONFIG	= apr-config
ORBIT2-CONFIG	= orbit2-config
ORBIT-IDL-2	= orbit-idl-2
IDLOUT	= ccReg.h ccReg-common.c ccReg-stubs.c
OBJS	= mod_whoisd.o whois-client.o ccReg-common.o ccReg-stubs.o
IDL	= ../cr/idl/ccReg.idl

ORB_LDFLAGS	= $(shell $(ORBIT2-CONFIG) --libs | sed -e s/-Wl,//g -e s/-pthread/-lpthread/g)
ORB_CFLAGS	= $(shell $(ORBIT2-CONFIG) --cflags)

AP_CFLAGS	 =$(shell $(APXS) -q CFLAGS)
AP_CFLAGS	+=$(shell $(APXS) -q CFLAGS_SHLIB)
AP_CFLAGS	+=$(shell $(APR-CONFIG) --cppflags)
AP_CFLAGS	+=$(shell $(APR-CONFIG) --cflags)
AP_INCLUDE	 =-I$(shell $(APXS) -q INCLUDEDIR)
AP_INCLUDE	+=$(shell $(APR-CONFIG) --includes)

AP_LDFLAGS	 =$(shell $(APXS) -q LDFLAGS_SHLIB)
AP_LDFLAGS	+=$(shell $(APR-CONFIG) --ldflags)
AP_LIBS	+=$(shell $(APR-CONFIG) --libs)

AP_INSTALLDIR	= $(shell $(APXS) -q LIBEXECDIR)

CFLAGS	= -g -O -fPIC -Wall
LDFLAGS	= -rpath $(AP_INSTALLDIR) -Bshareable

build: mod_whoisd.so

install: mod_whoisd.so
	cp -f mod_whoisd.so $(AP_INSTALLDIR)

mod_whoisd.so: $(OBJS)
	ld -o mod_whoisd.so $(LDFLAGS) $(AP_LDFLAGS) $(ORB_LDFLAGS) $(OBJS) $(AP_LIBS)

mod_whoisd.o:	mod_whoisd.c whois-client.h
	gcc $(CFLAGS) $(AP_CFLAGS) $(AP_INCLUDE) -c mod_whoisd.c

whois-client.o: whois-client.c whois-client.h ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c whois-client.c

ccReg-common.o: ccReg-common.c
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-common.c

ccReg-stubs.o: ccReg-stubs.c
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-stubs.c

$(IDLOUT):
	$(ORBIT-IDL-2) --noskels $(IDL)

clean:
	-rm -f $(OBJS)
	-rm -f $(IDLOUT)

distclean:
	-rm -f mod_whoisd.so
	-rm -f $(OBJS)
	-rm -f $(IDLOUT)

.PHONY: clean distclean install build
