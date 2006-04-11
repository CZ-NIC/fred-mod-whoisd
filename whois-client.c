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

static CORBA_ORB  global_orb = CORBA_OBJECT_NIL; /* global orb */
 

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
	free (objref);

        fclose (file);
        return obj;
}
 
/**
 * Get domain info. If there is no such a registered domain, NULL is
 * returned.
 * @par domain Domain to find
 * @par service Corba service
 * @par ev Corba environment
 * @par wd Whois data (domain info)
 */
static void
client_run(const char *domain, ccReg_Whois service, CORBA_Environment *ev,
		whois_data_t *wd)
{
        ccReg_DomainWhois *dm = NULL;

        dm =  ccReg_Whois_Domain(service , domain , ev);
	if (raised_exception(ev)) {
		if (dm != NULL) CORBA_free(dm);
		return;
	}

	/* check if there is such a registered domain */
	if (dm->stat == 1) {
		if ((wd->nameservers = malloc(dm->ns._length)) == NULL) {
			ev->_major = CORBA_SYSTEM_EXCEPTION;
			CORBA_free (dm);
			return;
		}
		wd->created = dm->created;
		wd->expired = dm->expired;
		wd->registrarName = strdup(dm->registrarName);
		wd->registrarUrl = strdup(dm->registrarUrl);
		memcpy(wd->nameservers, dm->ns._buffer, dm->ns._length);
		wd->ns_length = dm->ns._length;
	}

        CORBA_free (dm);
}

/*
 * main 
 */
int
whois_corba_call(const char *domain, whois_data_t *wd)
{
	CORBA_char filename[] = "/tmp/ccWhois.ref";
        CORBA_Environment ev[1];
        CORBA_exception_init(ev);
	ccReg_Whois e_service = CORBA_OBJECT_NIL;
	int	rc;

        global_orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		if (global_orb != CORBA_OBJECT_NIL)
			CORBA_ORB_destroy(global_orb, ev);
		return CORBA_INIT_FAILED;
	}

	e_service = (ccReg_Whois)
		import_object_from_file(global_orb, filename, ev);
	if (raised_exception(ev)) {
		/* releasing managed object */
		CORBA_Object_release(e_service, ev);
		/* tear down the ORB */
		if (global_orb != CORBA_OBJECT_NIL)
			CORBA_ORB_destroy(global_orb, ev);
		return CORBA_IMPORT_FAILED;
	}

	client_run(domain, e_service, ev, wd);

	/* was everything OK? */
	if (raised_exception(ev)) rc = CORBA_SERVICE_FAILED;
	else rc = CORBA_OK;
 
	/* releasing managed object */
	CORBA_Object_release(e_service, ev);
	/* tear down the ORB */
	if (global_orb != CORBA_OBJECT_NIL) CORBA_ORB_destroy(global_orb, ev);
 
        return rc;
}

void
whois_release_data(whois_data_t *wd)
{
	assert (wd != NULL);
	free(wd->registrarName);
	free(wd->registrarUrl);
	free(wd->nameservers);
}
