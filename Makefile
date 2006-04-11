APXS   = /usr/sbin/apxs
ORBIT2-CONFIG = orbit2-config
ORBIT-IDL-2   = orbit-idl-2
IDLOUT = ccReg.h ccReg-common.c ccReg-stubs.c
OBJS   = mod_whoisd.lo whois-client.lo whois-common.lo ccReg-stubs.lo
#IDL    = ../cr/idl/ccReg.idl
IDL    = ccReg.idl
CFLAGS = -g -O
ORB_LDFLAGS = $(shell $(ORBIT2-CONFIG) --libs)
ORB_CFLAGS  = $(shell $(ORBIT2-CONFIG) --cflags)
AP_CFLAGS  = -I$(shell $(APXS) -q INCLUDEDIR)
AP_LDFLAGS  = $(shell $(APXS) -q LDFLAGS_SHLIB)
AP_INSTALLDIR = $(shell $(APXS) -q LIBEXECDIR)

build: mod_whoisd.la

mod_whoisd.la: $(OBJS)
	libtool --mode=link gcc -o mod_whoisd.la -rpath $(AP_INSTALLDIR) $(OBJS) $(ORB_LDFLAGS) $(AP_LDFLAGS)

mod_whoisd.lo:	mod_whoisd.c whois-client.h
	libtool --mode=compile gcc $(CFLAGS) $(AP_CFLAGS) -c mod_whoisd.c

whois-client.lo: whois-client.c whois-client.h ccReg.h
	libtool --mode=compile gcc $(CFLAGS) $(ORB_CFLAGS) -c whois-client.c

ccReg-common.lo: ccReg-common.c 
	libtool --mode=compile gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-common.c

ccReg-stubs.lo: ccReg-stubs.c
	libtool --mode=compile gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-stubs.c

$(IDLOUT):
	$(ORBIT-IDL-2) --noskels $(IDL)

clean:
	-rm -f mod_whoisd.la
	-rm -f -r .libs
	-rm -f $(OBJS)
	-rm -f *.loT
	-rm -f $(IDLOUT)
