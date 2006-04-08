mod_whoisd.la: mod_whoisd.slo $(CORBA_OBJS)
	$(SH_LINK) $(LIBS) -rpath $(libexecdir) -module -avoid-version  mod_whoisd.lo $(CORBA_OBJS)
DISTCLEAN_TARGETS = modules.mk
shared =  mod_whoisd.la
