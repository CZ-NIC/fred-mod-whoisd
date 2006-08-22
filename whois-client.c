/**
 * Copyright statement ;)
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <orbit/orbit.h>

/* This header file was generated from the idl */
#include "ccReg.h"
#include "whois-client.h"

#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)


/**
 * Read string from stream.
 */
static gchar*
read_string_from_stream(FILE *stream)
{
	gulong length;
	gchar *objref;
	int c;
	int i = 0;

	length = 4 * 1024; /* should suffice ordinary IOR string */
	objref = g_malloc0(length * sizeof (gchar));
	if (objref == NULL) return NULL;

	/* skip leading white space */
	while ((c = fgetc(stream)) !=EOF && g_ascii_isspace(c));
	/* POST: c==EOF or c=first character */

	if (c != EOF) {
		/* append c to string while more c exist and c not white space */
		do {
			/* check size */
			if (i >= length - 1) {
				length *= 2;
				objref = g_realloc(objref, length);
			}
			objref[i++] = c;
		}while ((c = fgetc(stream)) != EOF && !g_ascii_isspace(c));
	}
	/* terminate string with \0 */
	objref[i] = '\0';

	return objref;
}


/**
 * Import object from file.
 */
static CORBA_Object
import_object_from_file (CORBA_ORB orb, CORBA_char *filename,
			      CORBA_Environment *ev)
{
        FILE         *file;
	gchar        *objref;
        CORBA_Object  obj = CORBA_OBJECT_NIL;
  
        if ((file = fopen(filename, "r")) == NULL) {
		ev->_major = CORBA_SYSTEM_EXCEPTION;
		return CORBA_OBJECT_NIL;		
     	}
	objref = read_string_from_stream(file);

	if (!objref || strlen(objref) == 0) {
		if (objref) g_free (objref);
		ev->_major = CORBA_SYSTEM_EXCEPTION;
		fclose (file);
		return CORBA_OBJECT_NIL;		
	}

	obj = (CORBA_Object) CORBA_ORB_string_to_object(orb, objref, ev);
	g_free (objref);

        fclose (file);
        return obj;
}
 
/**
 * Get domain info. If there is no such a registered domain, NULL is
 * returned.
 * @par service Corba service
 * @par ev Corba environment
 * @par wd Whois data (domain info)
 */
static void
client_run(ccReg_Whois service, CORBA_Environment *ev, whois_data_t *wd)
{
        ccReg_DomainWhois *dm;

        dm =  ccReg_Whois_Domain(service , wd->dname , ev);
	if (raised_exception(ev)) {
		/* do NOT try to free dm even if not NULL -> segfault */
		return;
	}

	/* check if there is such a registered domain */
	if (dm->status == 1) {
		int i;

		wd->valid = 1;
		if ((wd->nameservers = malloc((sizeof wd->nameservers[0]) *
						dm->ns._length)) == NULL) {
			ev->_major = CORBA_SYSTEM_EXCEPTION;
			CORBA_free (dm);
			return;
		}
		wd->created = dm->created;
		wd->expired = dm->expired;
		wd->registrarName = strdup(dm->registrarName);
		wd->registrarUrl = strdup(dm->registrarUrl);
		for (i = 0; i < dm->ns._length; i++)
			wd->nameservers[i] = strdup(dm->ns._buffer[i]);
		wd->ns_length = dm->ns._length;
	}
	else wd->valid = 0;

        CORBA_free (dm);
}

/* this one is called from wrapper bellow */
static int
whois_corba_call_int(whois_data_t *wd)
{
        CORBA_Environment ev[1];
        CORBA_exception_init(ev);
	CORBA_char filename[] = "/tmp/ccReg.ref";
	CORBA_ORB  global_orb = CORBA_OBJECT_NIL; /* global orb */
        ccReg_EPP epp_service = CORBA_OBJECT_NIL;
        ccReg_Whois whois_service  = CORBA_OBJECT_NIL;
	int	rc;
 

        global_orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		if (global_orb != CORBA_OBJECT_NIL)
			CORBA_ORB_destroy(global_orb, ev);
		return CORBA_INIT_FAILED;
	}






	epp_service = (ccReg_EPP)
		import_object_from_file(global_orb, filename, ev);
	if (raised_exception(ev)) {
		/* releasing managed object */
		CORBA_Object_release(epp_service, ev);
		/* tear down the ORB */
		if (global_orb != CORBA_OBJECT_NIL)
			CORBA_ORB_destroy(global_orb, ev);
		return CORBA_IMPORT_FAILED;
	}

        whois_service = (ccReg_Whois)  ccReg_EPP_getWhois( epp_service , ev);

        etk_abort_if_exception(ev, "getWhois service failed");


	client_run(whois_service, ev, wd);

	/* was everything OK? */
	if (raised_exception(ev)) rc = CORBA_SERVICE_FAILED;
	else rc = CORBA_OK;
 
	/* releasing managed object */
        CORBA_Object_release(whois_service, ev);
	CORBA_Object_release(epp_service, ev);
	/* tear down the ORB */
	if (global_orb != CORBA_OBJECT_NIL) CORBA_ORB_destroy(global_orb, ev);
 
        return rc;
}

/**
 * wrapper around whois_corba_call_int
 * The problem is probably in linking apache and corba together.
 * Parameters on stack are not handled properly, this wrapper solves
 * the problem for now, although it's dirty hack.
 */
int
whois_corba_call(whois_data_t *wd)
{
	return whois_corba_call_int(wd);
}

void
whois_release_data(whois_data_t *wd)
{
	int i;

	assert (wd != NULL);
	/* free everything except wd->dname which is handled in apache */
	free(wd->registrarName);
	free(wd->registrarUrl);
	for (i = 0; i < wd->ns_length; i++) {
		free(wd->nameservers[i]);
	}
	free(wd->nameservers);
}
