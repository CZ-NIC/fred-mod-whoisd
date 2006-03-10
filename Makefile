APXS=/home/loo/apache.org/chroot/bin/apxs
INC=/home/loo/apache.org/chroot/include

.PHONY: clean build install

build: mod_whoisd.c
	$(APXS) -c mod_whoisd.c

install: mod_whoisd.c
	$(APXS) -c -i mod_whoisd.c

clean:
	rm -f mod_whoisd.loT
	rm -f mod_whoisd.la
	rm -f mod_whoisd.lo
	rm -f mod_whoisd.o
	rm -f mod_whoisd.slo
	rm -rf .libs
