
/*
 * Echo client program.. Hacked by Ewan Birney <birney@sanger.ac.uk>
 * from echo test suite, update for ORBit2 by Frank Rehberger
 * <F.Rehberger@xtradyne.de>
 *
 * Client reads object reference (IOR) from local file 'echo.ior' and
 * forwards console input to echo-server. A dot . as single character
 * in input terminates the client.
 */


 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <orbit/orbit.h>

/*
 * This header file was generated from the idl
 */

#include "ccReg.h"
#include "whois-client.h"

static CORBA_ORB  global_orb = CORBA_OBJECT_NIL; /* global orb */
 
/* Is called in case of process signals. it invokes CORBA_ORB_shutdown()
 * function, which will terminate the processes main loop.
 */
static
void
client_shutdown (int sig)
{
        CORBA_Environment  local_ev[1];
        CORBA_exception_init(local_ev);
 
        if (global_orb != CORBA_OBJECT_NIL)
        {
                CORBA_ORB_shutdown (global_orb, FALSE, local_ev);
        }
}
 
        
/* Inits ORB @orb using @argv arguments for configuration. For each
 * ORBit options consumed from vector @argv the counter of @argc_ptr
 * will be decremented. Signal handler is set to call
 * echo_client_shutdown function in case of SIGINT and SIGTERM
 * signals.  If error occures @ev points to exception object on
 * return.
 */
static
void
client_init (CORBA_ORB         *orb,
             CORBA_Environment *ev)
{
        /* create Object Request Broker (ORB) */
        (*orb) = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
        if (etk_raised_exception(ev)) return;
}

/* Releases @servant object and finally destroys @orb. If error
 * occures @ev points to exception object on return.
 */
static
void
client_cleanup (CORBA_ORB                 orb,
                CORBA_Object              service,
                CORBA_Environment        *ev)
{
        /* releasing managed object */
        CORBA_Object_release(service, ev);
        if (etk_raised_exception(ev)) return;
 
        /* tear down the ORB */
        if (orb != CORBA_OBJECT_NIL)
        {
                /* going to destroy orb.. */
                CORBA_ORB_destroy(orb, ev);
                if (etk_raised_exception(ev)) return;
        }
}

/**
 *
 */
/* static */
/* CORBA_Object */
/* client_import_service_from_stream (CORBA_ORB          orb, */
/* 				   FILE              *stream, */
/* 				   CORBA_Environment *ev) */
/* { */
/* 	CORBA_Object obj = CORBA_OBJECT_NIL; */
/* 	gchar *objref=NULL; */
    
/* 	fscanf (stream, "%as", &objref);  /\* FIXME, handle input error *\/  */
	
/* 	obj = (CORBA_Object) CORBA_ORB_string_to_object (global_orb, */
/* 							 objref,  */
/* 							 ev); */
/* 	free (objref); */
	
/* 	return obj; */
/* } */

/**
 *

 */
/* static */
/* CORBA_Object */
/* client_import_service_from_file (CORBA_ORB          orb, */
/* 				 char              *filename, */
/* 				 CORBA_Environment *ev) */
/* { */
/*         CORBA_Object  obj    = NULL; */
/*         FILE         *file   = NULL; */
 
/*         /\* write objref to file *\/ */
         
/*         if ((file=fopen(filename, "r"))==NULL) */
/*                 g_error ("could not open %s\n", filename); */
    
/* 	obj=client_import_service_from_stream (orb, file, ev); */
	
/* 	fclose (file); */

/* 	return obj; */
/* } */


/**
 *
 */
static void client_run (const char *domain, ccReg_Whois service, CORBA_Environment *ev)
{
        ccReg_DomainWhois *dm;

        dm =  ccReg_Whois_Domain(service , domain , ev);
        fprintf(stderr, "get  [%s]  %s %s\n", dm->name, dm->registrarName, dm->ns);

        CORBA_free (dm);
}

/*
 * main 
 */
int
whois_corba_call(const char *domain)
{
	CORBA_char filename[] = "/tmp/ccWhois.ref";
        
	ccReg_Whois e_service = CORBA_OBJECT_NIL;

        CORBA_Environment ev[1];
        CORBA_exception_init(ev);

	/* XXX Should we check for client_cleanup success? */

	client_init (&global_orb, ev);
	if (etk_raised_exception(ev)) {
		if (global_orb != CORBA_OBJECT_NIL)
			CORBA_ORB_destroy(global_orb, ev);
		return CORBA_INIT_FAILED;
	}

	e_service = (ccReg_Whois) etk_import_object_from_file (global_orb,
							   filename,
							   ev);
	if (etk_raised_exception(ev)) {
		client_cleanup (global_orb, e_service, ev);
		return CORBA_IMPORT_FAILED;
	}

	client_run (domain, e_service, ev);

	if (etk_raised_exception(ev)) {
		client_cleanup (global_orb, e_service, ev);
		return CORBA_SERVICE_FAILED;
	}
 
	client_cleanup (global_orb, e_service, ev);
 
        return CORBA_OK;
}

int main(int argc, char *argv[]) { return 0; }
