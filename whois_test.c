#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <orbit/orbit.h>
#include <ORBitservices/CosNaming.h>

#include "whois-client.h"
#include "Whois.h"

#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)

ccReg_Whois
get_service(CORBA_ORB orb, const char *ns_loc, const char *obj_name)
{
    ccReg_Whois   service = CORBA_OBJECT_NIL; /* object's stub */
    CORBA_Environment   ev[1];
    CosNaming_NamingContext ns; /* used for nameservice */
    CosNaming_NameComponent *name_component; /* EPP's name */
    CosNaming_Name  *cos_name; /* Cos name used in service lookup */
    char    ns_string[150];
    
    CORBA_exception_init(ev);

    assert(ns_loc != NULL);
    assert(obj_name != NULL);

    /* build a name of EPP object */
    name_component = (CosNaming_NameComponent *)
        malloc(2 * sizeof(CosNaming_NameComponent));
    name_component[0].id = CORBA_string_dup("ccReg");
    name_component[0].kind = CORBA_string_dup("context");
    name_component[1].id = CORBA_string_dup(obj_name);
    name_component[1].kind = CORBA_string_dup("Object");
    cos_name = (CosNaming_Name *) malloc (sizeof(CosNaming_Name));
    cos_name->_maximum = cos_name->_length = 2;
    cos_name->_buffer = name_component;
    CORBA_sequence_set_release(cos_name, CORBA_TRUE);

    ns_string[149] = 0;
    snprintf(ns_string, 149, "corbaloc::%s/NameService", ns_loc);
    CORBA_exception_init(ev);

    /* get nameservice */
    ns = (CosNaming_NamingContext) CORBA_ORB_string_to_object(orb,
            ns_string, ev);
    if (ns == CORBA_OBJECT_NIL || raised_exception(ev)) {
        CORBA_exception_free(ev);
        return NULL;
    }
    /* get EPP object */
    service =(ccReg_Whois) CosNaming_NamingContext_resolve(ns, cos_name, ev);
    if (service == CORBA_OBJECT_NIL || raised_exception(ev)) {
        CORBA_exception_free(ev);
        /* release nameservice */
        CORBA_Object_release(ns, ev);
        CORBA_exception_free(ev);
        return NULL;
    }
    /* release nameservice */
    CORBA_Object_release(ns, ev);
    CORBA_exception_free(ev);
    
    return service;
}

int
main(int argc, char *argv[])
{
	CORBA_Environment ev[1];
	ccReg_Whois	 service;
	CORBA_ORB	 orb;
	whois_data_t	*wd;
	char	buf[100];
	int	i, quit;
	const char	*host = NULL;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h")) {
			if (++i < argc) {
				host = argv[i];
				i++;
			}
			break;
		}
	}
	if (host == NULL)
		host = "localhost";

	CORBA_exception_init(ev);
	orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		fputs("ORB initialization error\n", stderr);
		return 3;
	}

	quit = 0;
	/* do the work */
	for (; i < argc; i++) {
		int	ret;

		service = get_service(orb, host, "Whois");
		if (service == NULL) {
			fprintf(stderr, "Error when getting reference\n");
			return 3;
		}

		ret = whois_corba_call(service, argv[i], &wd, buf, 100);
		switch (ret) {
			case CORBA_OK:
				printf("Domain '%s' is REGISTERED\n", argv[i]);
				whois_release_data(wd);
				break;
			case CORBA_DOMAIN_FREE:
				printf("Domain '%s' is FREE\n", argv[i]);
				break;
			case CORBA_DOMAIN_INVALID:
				printf("Domain '%s' is INVALID\n", argv[i]);
				break;
			case CORBA_DOMAIN_LONG:
				printf("Domain '%s' is LONG\n", argv[i]);
				break;
			case CORBA_DOMAIN_BAD_ZONE:
				printf("Domain '%s' is in BAD ZONE\n", argv[i]);
				break;
			case CORBA_UNKNOWN_ERROR:
				fprintf(stderr, "Unknown ERROR from server\n");
				quit = 1;
				break;
			case CORBA_SERVICE_FAILED:
				fprintf(stderr, "CORBA service failed\n");
				quit = 2;
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
		CORBA_Object_release(service, ev);
		CORBA_exception_free(ev);
		if (quit) break;
	}
	CORBA_ORB_destroy(orb, ev);
	CORBA_exception_free(ev);

	return quit;
}
