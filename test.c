#include <stdio.h>
#include <unistd.h>
#include "whois-client.h"


int
main(int argc, char *argv[])
{
	whois_corba_globs	*globs;
	whois_data_t	*wd;
	char	buf[100];
	int	i, quit;

	globs = whois_corba_init("localhost", "PyWhois");
	if (globs == NULL) {
		fprintf(stderr, "Error in CORBA initialization\n");
		exit(2);
	}
	quit = 0;
	/* do the work */
	for (i = 1; i < argc; i++) {
		int	ret;

		ret = whois_corba_call(globs, argv[i], &wd, buf, 100);
		switch (ret) {
			case CORBA_OK:
				printf("Domain '%s' is REGISTERED\n", argv[i]);
				whois_release_data(wd);
				break;
			case CORBA_DOMAIN_FREE:
				printf("Domain '%s' is FREE\n", argv[i]);
				break;
			case CORBA_SERVICE_FAILED:
				fprintf(stderr, "CORBA service failed\n");
				quit = 1;
				break;
			case CORBA_INTERNAL_ERROR:
				fprintf(stderr, "Malloc failed\n");
				quit = 1;
				break;
			default:
				fprintf(stderr, "Unknown return code\n");
				quit = 1;
				break;
		}
		if (quit) break;
	}
	whois_corba_init_cleanup(globs);
	return (quit) ? 1 : 0;
}
