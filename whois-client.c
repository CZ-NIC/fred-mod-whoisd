/**
 * @file whois-client.c
 *
 * Implementation of CORBA backend used for querying CORBA server for
 * information about domain.
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <orbit/orbit.h>
#include <ORBitservices/CosNaming.h>

/* This header file was generated from the idl */
#include "whois-client.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/** A shortcut for testing of CORBA exception appearence. */
#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)
/** Maximal # of retries when COMM_FAILURE exception during CORBA call occurs. */
#define MAX_RETRIES	3
/** Sleep interval in microseconds between retries. */
#define RETR_SLEEP	100000
/** True if CORBA exception is COMM_FAILURE, which is used in retry loop. */
#define IS_NOT_COMM_FAILURE_EXCEPTION(_ev)                             \
	(strcmp((_ev)->_id, "IDL:omg.org/CORBA/COMM_FAILURE:1.0"))
/** True if CORBA exception is DomainNotFound */
#define IS_DOMAIN_ERROR(_ev)                             \
	(!strcmp((_ev)->_id, "IDL:ccReg/Whois/DomainError:1.0"))


int
whois_corba_call(service_Whois service, const char *dname, whois_data_t **wd,
		char *timebuf, unsigned timebuflen)
{
	CORBA_Environment ev[1];
	CORBA_string	timestamp;
	whois_data_t	*wd_temp;
	ccReg_DomainWhois *dm; /* domain data */
	int	retr; /* retry counter */
	int	i;
 
	assert(service != NULL);
	assert(dname != NULL);
	assert(timebuf != NULL);
	assert(timebuflen > 0);

	*wd = NULL;
	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call domain method */
		dm = ccReg_Whois_getDomain((ccReg_Whois) service,
				dname, &timestamp,ev);

		/* if COMM_FAILURE is not raised then quit retry loop*/
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		int ret;
		if (IS_DOMAIN_ERROR(ev)) {
			ccReg_Whois_DomainError	*de;

			de = (ccReg_Whois_DomainError *) ev->_any._value;
			/* get timestamp */
			timebuf[timebuflen - 1] = '\0';
			strncpy(timebuf, de->timestamp, timebuflen - 1);
			switch (de->type) {
				case ccReg_WE_DOMAIN_BAD_ZONE:
					ret = CORBA_DOMAIN_BAD_ZONE;
					break;
				case ccReg_WE_DOMAIN_LONG:
					ret = CORBA_DOMAIN_LONG;
					break;
				case ccReg_WE_INVALID:
					ret = CORBA_DOMAIN_INVALID;
					break;
				case ccReg_WE_NOTFOUND:
					ret = CORBA_DOMAIN_FREE;
					break;
				default:
					ret = CORBA_UNKNOWN_ERROR;
					break;
			}
		}
		else
			ret = CORBA_SERVICE_FAILED;
		CORBA_exception_free(ev);
		return ret;
	}
	CORBA_exception_free(ev);

	/* get time of response generation */
	timebuf[timebuflen - 1] = '\0';
	strncpy(timebuf, timestamp, timebuflen - 1);
	CORBA_free(timestamp);

	/* allocate all needed items */
	if ((*wd = (whois_data_t *) calloc(1, sizeof **wd)) == NULL) {
		CORBA_free(dm);
		return CORBA_INTERNAL_ERROR;
	}
	wd_temp = *wd;
	wd_temp->fqdn = strdup(dm->fqdn);
	wd_temp->enum_domain = dm->enum_domain;
	wd_temp->nameservers = malloc(sizeof(char *) * dm->ns._length);
	if ((wd_temp)->nameservers == NULL) {
		CORBA_free(dm);
		free(wd_temp);
		*wd = NULL;
		return CORBA_INTERNAL_ERROR;
	}
	wd_temp->techs = malloc(sizeof(char *) * dm->tech._length);
	if (wd_temp->techs == NULL) {
		CORBA_free(dm);
		free(wd_temp->nameservers);
		free(wd_temp);
		*wd = NULL;
		return CORBA_INTERNAL_ERROR;
	}
	/* copy nameservers */
	for (i = 0; i < dm->ns._length; i++)
		wd_temp->nameservers[i] = strdup(dm->ns._buffer[i]);
	wd_temp->ns_length = dm->ns._length;
	/* copy technical contacts */
	for (i = 0; i < dm->tech._length; i++)
		wd_temp->techs[i] = strdup(dm->tech._buffer[i]);
	/* copy the rest of the items */
	wd_temp->tech_length = dm->tech._length;
	wd_temp->created = strdup(dm->created);
	wd_temp->expired = strdup(dm->expired);
	wd_temp->registrarName = strdup(dm->registrarName);
	wd_temp->registrarUrl = strdup(dm->registrarUrl);
	/* map status value */
	if (dm->status == ccReg_WHOIS_ACTIVE)
		wd_temp->status = DOMAIN_ACTIVE;
	else
		wd_temp->status = DOMAIN_EXPIRED;


        CORBA_free(dm);
        return CORBA_OK;
}

void
whois_release_data(whois_data_t *wd)
{
	int i;

	assert (wd != NULL);

	free(wd->fqdn);
	free(wd->registrarName);
	free(wd->registrarUrl);
	free(wd->created);
	free(wd->expired);
	for (i = 0; i < wd->ns_length; i++) {
		free(wd->nameservers[i]);
	}
	free(wd->nameservers);
	for (i = 0; i < wd->tech_length; i++) {
		free(wd->techs[i]);
	}
	free(wd->techs);
	free(wd);
}
