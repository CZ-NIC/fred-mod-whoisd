/*
 *  Copyright (C) 2007  CZ.NIC, z.s.p.o.
 *
 *  This file is part of FRED.
 *
 *  FRED is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2 of the License.
 *
 *  FRED is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * @file whois-client.c
 *
 * Implementation of CORBA backend used for querying CORBA server for
 * information about an object.
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <orbit/orbit.h>
#include <ORBitservices/CosNaming.h>

/* This header file was generated from the idl  */
#include "whois-client.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/** Max registrar handle length of MojeID registrar */
#define REG_HANDLE_MAX_LEN 1024

/** ID of object status 'Linked' */
#define ID_STATUS_OBJ_LINKED 16

/** A shortcut for testing of CORBA exception appearence. */
#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)
/** Max # of retries when COMM_FAILURE exception during CORBA call occurs. */
#define MAX_RETRIES	3
/** Sleep interval in microseconds between retries. */
#define RETR_SLEEP	100000
/** True if CORBA exception is COMM_FAILURE, which is used in retry loop. */
#define IS_NOT_COMM_FAILURE_EXCEPTION(_ev)                             \
	(strcmp((_ev)->_id, "IDL:omg.org/CORBA/COMM_FAILURE:1.0"))
/** True if CORBA exception is ObjectNotFound */
#define IS_OBJECT_NOT_FOUND(_ev)                             \
	(!strcmp((_ev)->_id, "IDL:ccReg/Whois/ObjectNotFound:1.0"))

/** Call strdup on string only if it is not empty, otherwise return NULL. */
#define NULL_STRDUP(src)	((*(src) == '\0') ? NULL : strdup(src))

/** maximum length of a string containing IP address
 */
const int IP_ADDR_LEN = 39;


/** code of the servie according to the database table `service'
 */
const int LC_UNIX_WHOIS = 0;

// for IPv4:
// const int IP_ADDR_LEN = 15;

#if 0
/**
 * This routine was written as a simple test of generator part and can be used
 * for testing.
 *
 * @param service    Whois CORBA object reference (not used).
 * @param wr         Whois request (not used).
 * @param objects    Array of resulting objects.
 * @param timebuf    Timestamp.
 * @return           Status.
 */
int
whois_corba_call(service_Whois service, const whois_request *wr,
		general_object *objects, char *timebuf, char *errmsg)
{
	assert(timebuf != NULL);

	/* XXX Temporary hack */
	strncpy(timebuf, "DUMMY:TIME", TIME_BUFFER_LENGTH);

	/* testing domain */
	objects[0].type = T_DOMAIN;
	objects[0].obj.d.domain = strdup("test-domain.cz");
	objects[0].obj.d.registrant = strdup("USER-HANDLE");
	objects[0].obj.d.admin_c = (char **) malloc(4 * sizeof (char *));
	objects[0].obj.d.admin_c[0] = strdup("ADMIN1-HANDLE");
	objects[0].obj.d.admin_c[1] = strdup("ADMIN2-HANDLE");
	objects[0].obj.d.admin_c[2] = strdup("POPOKATE");
	objects[0].obj.d.admin_c[3] = NULL;
	objects[0].obj.d.temp_c = (char **) malloc(2 * sizeof (char *));
	objects[0].obj.d.temp_c[0] = strdup("OLD-BURDEN");
	objects[0].obj.d.temp_c[1] = NULL;
	objects[0].obj.d.nsset = strdup("NSSET-HANDLE");
	objects[0].obj.d.registrar = strdup("REG-HANDLE");
	objects[0].obj.d.status = (char **) malloc(3 * sizeof (char *));
	objects[0].obj.d.status[0] = strdup("status1");
	objects[0].obj.d.status[1] = strdup("another_status");
	objects[0].obj.d.status[2] = NULL;
	objects[0].obj.d.registered = strdup("22.04.2007 23:00:12");
	objects[0].obj.d.changed = strdup("12.02.2008 03:10:43");
	objects[0].obj.d.expire = strdup("02.06.2009");
	objects[0].obj.d.validated_to = NULL;

	/* testing nsset */
	objects[1].type = T_NSSET;
	objects[1].obj.n.nsset = strdup("NSSET-HANDLE");
	objects[1].obj.n.nserver = (char **) malloc(3 * sizeof (char *));
	objects[1].obj.n.nserver[0] = strdup("ns1.bazmecek.net");
	objects[1].obj.n.nserver[1] = strdup("ns2.hosting.cz");
	objects[1].obj.n.nserver[2] = NULL;
	objects[1].obj.n.tech_c = (char **) malloc(4 * sizeof (char *));
	objects[1].obj.n.tech_c[0] = strdup("TECH1-HANDLE");
	objects[1].obj.n.tech_c[1] = strdup("TECH1-HANDLE");
	objects[1].obj.n.tech_c[2] = strdup("PETL");
	objects[1].obj.n.tech_c[3] = NULL;
	objects[1].obj.n.registrar = strdup("REG-HANDLE");
	objects[1].obj.n.created = strdup("22.04.2007 23:00:12");
	objects[1].obj.n.changed = strdup("12.02.2008 03:10:43");

	/* testing contact */
	objects[2].type = T_CONTACT;
	objects[2].obj.c.contact = strdup("CONTACT-HANDLE");
	objects[2].obj.c.org = strdup("Company Comercial 1th s.r.o.");
	objects[2].obj.c.name = strdup("Frank Lumpard");
	objects[2].obj.c.address = (char **) malloc(4 * sizeof (char *));
	objects[2].obj.c.address[0] = strdup("Ohio street n. 29");
	objects[2].obj.c.address[1] = strdup("New York");
	objects[2].obj.c.address[2] = strdup("400 11");
	objects[2].obj.c.address[3] = NULL;
	objects[2].obj.c.phone = strdup("+420778234800");
	objects[2].obj.c.fax_no = NULL;
	objects[2].obj.c.e_mail = strdup("frankl@noodle.com");
	objects[2].obj.c.registrar = strdup("REG-DEUTSCHE-TELEKOM");
	objects[2].obj.c.created = strdup("22.04.2007 23:00:12");
	objects[2].obj.c.changed = strdup("12.02.2008 03:10:43");

	/* testing registrar */
	objects[3].type = T_REGISTRAR;
	objects[3].obj.r.registrar = strdup("REG-HANDLE");
	objects[3].obj.r.org = strdup("deadly domains ltd.");
	objects[3].obj.r.url = strdup("http://www.undeadly.org/");
	objects[3].obj.r.phone = strdup("+420222573000");
	objects[3].obj.r.address = (char **) malloc(4 * sizeof (char *));
	objects[3].obj.r.address[0] = strdup("Bangladesha 29");
	objects[3].obj.r.address[1] = strdup("Old York Town");
	objects[3].obj.r.address[2] = strdup("530 01");
	objects[3].obj.r.address[3] = NULL;

	/* finish */
	objects[4].type = T_NONE;

	return CORBA_OK;
}
#endif

/**
 * Check for duplicates in array of objects.
 *
 * @param type       Which type of objects to look for.
 * @param handle     Handle of the object.
 * @param objects    The structure for holding any type of object
 * @param index_free First free item in array of objects.
 * @return           0 if no duplicates are present, 1 otherwise.
 */
int check_duplicates(int type, char *handle, general_object *objects, int index_free)
{
	int j;

	switch (type) {
		case T_CONTACT:
			for (j = 0; j < index_free; j++)
				if (objects[j].type == T_CONTACT &&
						strcmp(objects[j].obj.c.contact, handle) == 0) {
					return 1;
				}

			break;
		case T_REGISTRAR:
			for (j = 0; j < index_free; j++)
				if (objects[j].type == T_REGISTRAR &&
						strcmp(objects[j].obj.r.registrar, handle) == 0) {
					return 1;
				}

			break;
		case T_NSSET:
			for (j = 0; j < index_free; j++)
				if (objects[j].type == T_NSSET &&
						strcmp(objects[j].obj.n.nsset, handle) == 0) {
					return 1;
				}

			break;
		case T_KEYSET:
			for (j = 0; j < index_free; j++)
				if (objects[j].type == T_KEYSET &&
						strcmp(objects[j].obj.k.keyset, handle) == 0) {
					return 1;
				}

			break;
		case T_DOMAIN:
			for (j = 0; j < index_free; j++)
				if (objects[j].type == T_DOMAIN &&
						strcmp(objects[j].obj.d.domain, handle) == 0) {
					return 1;
				}

			break;
	}
	// j == index_free,  no duplicates found
	return 0;
}

/**
 * Search registrar by handle. Supress duplicities in array of objects.
 *
 * @param service    Whois CORBA object reference.
 * @param handle     Handle of registrar.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @return           Status.
 */
static int
get_registrar_by_handle(service_Whois service, const char *handle,
		general_object *objects, int *index_free, char *errmsg)
{
	CORBA_Environment	 ev[1];
	ccReg_WhoisRegistrar	*c_registrar; /* registrar detail */
	obj_registrar	*r;
	int	 retr;  /* retry counter */
	int	 line;
	int	 ret;   /* return code used in some cases */

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call registrar method */
		c_registrar = ccReg_Whois_getRegistrarByHandle(
				(ccReg_Whois) service, handle, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		if (IS_OBJECT_NOT_FOUND(ev))
			ret = CORBA_OK;
		else {
			ret = CORBA_SERVICE_FAILED;
			strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
			errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		}
		CORBA_exception_free(ev);
		return ret;
	}
	CORBA_exception_free(ev);

	if(!check_duplicates(T_REGISTRAR, c_registrar->handle, objects, *index_free)) {
		/* copy registrar data */
		objects[*index_free].type = T_REGISTRAR;
		r = &objects[*index_free].obj.r;
		r->registrar = NULL_STRDUP(c_registrar->handle);
		r->org = NULL_STRDUP(c_registrar->organization);
		r->url = NULL_STRDUP(c_registrar->url);
		r->phone = NULL_STRDUP(c_registrar->telephone);
		/* address is more complicated, it is composed from more items */
		r->address = (char **) malloc(8 * sizeof (char *));
		line = 0;
		#define COPY_ADDRESS_LINE(str) \
		do{ if (*(str) != '\0') r->address[line++] = strdup(str); }while(0)
		COPY_ADDRESS_LINE(c_registrar->street1);
		COPY_ADDRESS_LINE(c_registrar->street2);
		COPY_ADDRESS_LINE(c_registrar->street3);
		COPY_ADDRESS_LINE(c_registrar->city);
		COPY_ADDRESS_LINE(c_registrar->postalcode);
		COPY_ADDRESS_LINE(c_registrar->stateorprovince);
		COPY_ADDRESS_LINE(c_registrar->country);
		#undef COPY_ADDRESS_LINE
		r->address[line] = NULL;
		(*index_free)++;
	}

	CORBA_free(c_registrar);
	return CORBA_OK;
}

/**
 * Search contact by handle. Supress duplicities in array of objects.
 *
 * @param service    Whois CORBA object reference.
 * @param handle     Handle of contact.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
static int
get_contact_by_handle(service_Whois service, const char *handle,
		general_object *objects, int *index_free, char *errmsg,
		char* reg_mojeid_handle)
{
	CORBA_Environment	 ev[1];
	ccReg_ContactDetail	*c_contact; /* contact detail */
	obj_contact	*c;
	int	 retr;  /* retry counter */
	int	 ret;   /* return code used in some cases */
	int	 line;

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call contact method */
		c_contact = ccReg_Whois_getContactByHandle((ccReg_Whois)service,
				handle, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		if (IS_OBJECT_NOT_FOUND(ev))
			ret = CORBA_OK;
		else {
			ret = CORBA_SERVICE_FAILED;
			strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
			errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		}
		CORBA_exception_free(ev);
		return ret;
	}
	CORBA_exception_free(ev);
        if(!check_duplicates(T_CONTACT, c_contact->handle, objects, *index_free)) {

                int i = 0;

                objects[*index_free].type = T_CONTACT;
		c = &objects[*index_free].obj.c;
		c->contact = NULL_STRDUP(c_contact->handle);

                c->disclose = 0;

                // don't show data for contacts which are under MojeID registrar and 
                // at the same time 
                if(strncmp(c_contact->registrarHandle, reg_mojeid_handle, REG_HANDLE_MAX_LEN )) {
                    c->disclose = 1;
                } else {
                    for (i=0;i<c_contact->statusList._length;i++) {
                        if (c_contact->statusList._buffer[i] == ID_STATUS_OBJ_LINKED) {
                            c->disclose = 1;
                            break;
                        }
                    }
                }

                
                if(c->disclose != 0) {
                    /* copy contact data according to disclose flags */
                    if (c_contact->discloseOrganization)
                            c->org = NULL_STRDUP(c_contact->organization);
                    else
                            c->org = NULL;
                    if (c_contact->discloseName)
                            c->name = NULL_STRDUP(c_contact->name);
                    else
                            c->name = NULL;
                    if (c_contact->discloseTelephone)
                            c->phone = NULL_STRDUP(c_contact->telephone);
                    else
                            c->phone = NULL;
                    if (c_contact->discloseFax)
                            c->fax_no = NULL_STRDUP(c_contact->fax);
                    else
                            c->fax_no = NULL;
                    if (c_contact->discloseEmail)
                            c->e_mail = NULL_STRDUP(c_contact->email);
                    else
                            c->e_mail = NULL;
                    c->registrar = NULL_STRDUP(c_contact->registrarHandle);
                    c->created = NULL_STRDUP(c_contact->createDate);
                    c->changed = NULL_STRDUP(c_contact->updateDate);
                    /* address is more complicated, it is composed from more items */
                    c->address = (char **) malloc(8 * sizeof (char *));
                    line = 0;
                    if (c_contact->discloseAddress) {
            /** Copy contact information from CORBA structure to the data type for whois response
            */
            #define COPY_ADDRESS_LINE(str) \
                    do{ if (*(str) != '\0') c->address[line++] = strdup(str); }while(0)
                            COPY_ADDRESS_LINE(c_contact->street1);
                            COPY_ADDRESS_LINE(c_contact->street2);
                            COPY_ADDRESS_LINE(c_contact->street3);
                            COPY_ADDRESS_LINE(c_contact->city);
                            COPY_ADDRESS_LINE(c_contact->postalcode);
                            COPY_ADDRESS_LINE(c_contact->province);
                            COPY_ADDRESS_LINE(c_contact->country);
            #undef COPY_ADDRESS_LINE
                    }
                    c->address[line] = NULL;


                } else {
                    // don't disclose the contact data
                    c->disclose = 0;
                }

		(*index_free)++;
	}

	CORBA_free(c_contact);

	return CORBA_OK;
}

/**
 * Copy corba representation of nsset object to our representation.
 *
 * @param obj         Field in object array which is destination of copy.
 * @param c_nsset     Nsset detail returned from CORBA.
 */
static void
copy_nsset(general_object *obj, ccReg_NSSetDetail *c_nsset)
{
	const int 	IP_ADDR_LEN_SEP = IP_ADDR_LEN + 2;
		/* length of IP address string including separator (`, ') */
	obj_nsset	*n;
	int	 	i, j;

	/* copy nsset data */
	obj->type = T_NSSET;
	n = &obj->obj.n;
	n->nsset = NULL_STRDUP(c_nsset->handle);
	n->registrar = NULL_STRDUP(c_nsset->registrarHandle);
	n->created = NULL_STRDUP(c_nsset->createDate);
	n->changed = NULL_STRDUP(c_nsset->updateDate);
	n->nserver = (char **)
		malloc((c_nsset->hosts._length + 1) * sizeof (char *));
	n->nserver_addrs = (char **)
		malloc((c_nsset->hosts._length + 1) * sizeof (char *));
	memset (n->nserver_addrs, 0, (c_nsset->hosts._length + 1) * sizeof (char *) );

	for (i = 0; i < c_nsset->hosts._length; i++) {
		ccReg_InetAddress *addrs;

		n->nserver[i] = strdup(c_nsset->hosts._buffer[i].fqdn);

		addrs = &c_nsset->hosts._buffer[i].inet;
		if(addrs->_length > 0) {
			n->nserver_addrs[i] = (char*)malloc(addrs->_length * IP_ADDR_LEN_SEP + 1);
			n->nserver_addrs[i][0] = '\0';

			strncpy(n->nserver_addrs[i], addrs->_buffer[0], IP_ADDR_LEN + 1);
			for(j=1; j<addrs->_length; j++) {
				strncat(n->nserver_addrs[i], ", ", 3);
				strncat(n->nserver_addrs[i], addrs->_buffer[j], IP_ADDR_LEN + 1);
			}
		}
	}
	n->nserver[i] = NULL;
	n->nserver_addrs[i] = NULL;
	n->tech_c = (char **)
		malloc((c_nsset->admins._length + 1) * sizeof (char *));
	for (i = 0; i < c_nsset->admins._length; i++)
		n->tech_c[i] = strdup(c_nsset->admins._buffer[i]);
	n->tech_c[i] = NULL;
}

/**
 * Copy corba representation of keyset object to our representation.
 *
 * @param obj         Field in object array which is destination of copy.
 * @param c_keyset    Keyset detail returned from CORBA.
 */
static void
copy_keyset(general_object *obj, ccReg_KeySetDetail  *c_keyset)
{
	obj_keyset *k;
	keyset_dsrecord *ds;
	keyset_dnskey *key;
	int	 i, len;

	/* copy keyset data */
	obj->type = T_KEYSET;
	k = &obj->obj.k;
	k->keyset = NULL_STRDUP(c_keyset->handle);
	k->registrar = NULL_STRDUP(c_keyset->registrarHandle);
	k->created = NULL_STRDUP(c_keyset->createDate);
	k->changed = NULL_STRDUP(c_keyset->updateDate);

	len = c_keyset->dsrecords._length + 1;

	ds = k->ds = (keyset_dsrecord*)malloc(len * sizeof(keyset_dsrecord));

	for (i = 0; i < (len - 1); i++, ds++) {
		ds->key_tag = c_keyset->dsrecords._buffer[i].keyTag;
		ds->digest = strdup(c_keyset->dsrecords._buffer[i].digest);
		ds->alg = c_keyset->dsrecords._buffer[i].alg;
		ds->digest_type = c_keyset->dsrecords._buffer[i].digestType;
		ds->max_sig_life = c_keyset->dsrecords._buffer[i].maxSigLife;
	}
	ds->key_tag = -1;
	ds->digest = NULL;
	ds->alg = -1;
	ds->digest_type = -1;
	ds->max_sig_life = -1;

	len = c_keyset->dnskeys._length + 1;

	key = k->keys = (keyset_dnskey*)malloc(len * sizeof(keyset_dnskey));

	for (i = 0; i < (len - 1); i++, key++) {
		key->flags = c_keyset->dnskeys._buffer[i].flags;
		key->protocol = c_keyset->dnskeys._buffer[i].protocol;
		key->alg = c_keyset->dnskeys._buffer[i].alg;
		key->public_key = strdup(c_keyset->dnskeys._buffer[i].key);
	}
	key->public_key = NULL;
	key->flags = -1;
	key->protocol = -1;
	key->alg = -1;

	k->tech_c = (char **)
		malloc((c_keyset->admins._length + 1) * sizeof (char *));
	for (i = 0; i < c_keyset->admins._length; i++)
		k->tech_c[i] = strdup(c_keyset->admins._buffer[i]);
	k->tech_c[i] = NULL;
}

/**
 * The function does recursion on nsset.
 *
 * @param service     Whois corba object reference.
 * @param rec	      Switches recursion on/off
 * @param n           Nsset object on which is done recursion.
 * @param objects     Array of results.
 * @param index_free  First free index in array of results.
 * @param errmsg      Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return            Status.
 */
static int
recurse_nsset(service_Whois service, int rec, obj_nsset *n,
		general_object *objects, int *index_free, char *errmsg,
		char *reg_mojeid_handle)
{
	int	 i, ret;

	if (*index_free >= MAX_OBJECT_COUNT)
		return CORBA_OK_LIMIT;
	if (!rec)
		return CORBA_OK;

	/* recursion on tech_c */
	for (i = 0; n->tech_c[i] != NULL; i++) {
		ret = get_contact_by_handle(service, n->tech_c[i],
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK) return ret;
	}

	return CORBA_OK;
}

/**
 * The function does recursion on keyset.
 *
 * @param service     Whois corba object reference.
 * @param rec	      Switches recursion on/off
 * @param k           Keyset object on which recursion is done.
 * @param objects     Array of results.
 * @param index_free  First free index in array of results.
 * @param errmsg      Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return            Status.
 */
static int
recurse_keyset(service_Whois service, int rec, obj_keyset *k,
		general_object *objects, int *index_free, char *errmsg,
		char * reg_mojeid_handle)
{
	int	 i, ret;

	if (*index_free >= MAX_OBJECT_COUNT)
		return CORBA_OK_LIMIT;
	if (!rec)
		return CORBA_OK;

	/* recursion on tech_c */
	for (i = 0; k->tech_c[i] != NULL; i++) {
		ret = get_contact_by_handle(service, k->tech_c[i],
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK) return ret;
	}

	return CORBA_OK;
}

/**
 * Search nsset by handle and dependent objects if recursion is switched on. Supress duplicities in array of objects.
 *
 * @param service    Whois CORBA object reference.
 * @param handle     Handle of nsset.
 * @param rec        Recursive lookup is performed if true.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
static int
get_nsset_by_handle(service_Whois service, const char *handle, int rec,
		general_object *objects, int *index_free, char *errmsg,
		char *reg_mojeid_handle)
{
	CORBA_Environment	 ev[1];
	ccReg_NSSetDetail	*c_nsset; /* nsset detail */
	int	 retr;  /* retry counter */
	int	 ret;   /* return code used in some cases */

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call nsset method */
		c_nsset = ccReg_Whois_getNSSetByHandle((ccReg_Whois) service,
				handle, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		if (IS_OBJECT_NOT_FOUND(ev))
			ret = CORBA_OK;
		else {
			ret = CORBA_SERVICE_FAILED;
			strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
			errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		}
		CORBA_exception_free(ev);
		return ret;
	}
	CORBA_exception_free(ev);

	if(!check_duplicates(T_NSSET, c_nsset->handle, objects, *index_free)) {
		copy_nsset(&objects[(*index_free)++], c_nsset);
		CORBA_free(c_nsset);

		return recurse_nsset(service, rec, &objects[*index_free - 1].obj.n,
			objects, index_free, errmsg, reg_mojeid_handle);
	} else {
		CORBA_free(c_nsset);
		return CORBA_OK;
	}
}

/**
 * Search keyset by handle and dependent objects if recursion is switched on. Supress duplicities in array of objects.
 *
 * @param service    Whois CORBA object reference.
 * @param handle     Handle of keyset.
 * @param rec        Recursive lookup is performed if true.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
static int
get_keyset_by_handle(service_Whois service, const char *handle, int rec,
		general_object *objects, int *index_free, char *errmsg,
		char *reg_mojeid_handle)
{
	CORBA_Environment	 ev[1];
	ccReg_KeySetDetail	*c_keyset; /* keyset detail */
	int	 retr;  /* retry counter */
	int	 ret;   /* return code used in some cases */

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call keyset method */
		c_keyset = ccReg_Whois_getKeySetByHandle((ccReg_Whois) service,
				handle, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		if (IS_OBJECT_NOT_FOUND(ev))
			ret = CORBA_OK;
		else {
			ret = CORBA_SERVICE_FAILED;
			strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
			errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		}
		CORBA_exception_free(ev);
		return ret;
	}
	CORBA_exception_free(ev);

	if(!check_duplicates(T_KEYSET, c_keyset->handle, objects, *index_free)) {
		copy_keyset(&objects[(*index_free)++], c_keyset);
		CORBA_free(c_keyset);
		return recurse_keyset(service, rec, &objects[*index_free - 1].obj.k,
			objects, index_free, errmsg, reg_mojeid_handle);

	} else {

		CORBA_free(c_keyset);
		return CORBA_OK;
	}

}


/**
 * Search nsset by its attribute and dependent objects if recursion is
 * switched on.
 *
 * @param service    Whois CORBA object reference.
 * @param key        Attribute of nsset.
 * @param attr       Attribute type.
 * @param rec        Recursive lookup is performed if true.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
static int
get_nsset_by_attr(service_Whois service,
		const char *key,
		ccReg_NSSetInvKeyType attr,
		int rec,
		general_object *objects,
		int *index_free, char *errmsg,
		char *reg_mojeid_handle)
{
	CORBA_Environment	 ev[1];
	ccReg_NSSetDetails	*c_nssets; /* nsset details */
	int	 retr;  /* retry counter */
	int	 i;
	int	 ret;

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call nsset method */
		c_nssets = ccReg_Whois_getNSSetsByInverseKey(
				(ccReg_Whois) service, key, attr,
				MAX_OBJECT_COUNT - *index_free, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
		return CORBA_SERVICE_FAILED;
	}
	CORBA_exception_free(ev);

	ret = CORBA_OK;
	/* copy all returned nssets */
	for (i = 0; i < c_nssets->_length && *index_free < MAX_OBJECT_COUNT; i++)
	{
		copy_nsset(&objects[(*index_free)++], &c_nssets->_buffer[i]);
		ret = recurse_nsset(service, rec,
				&objects[(*index_free) - 1].obj.n,
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK)
			break;
	}

	CORBA_free(c_nssets);

	return ret;
}

/**
 * Search keyset by its attribute and dependent objects if recursion is
 * switched on.
 *
 * @param service    Whois CORBA object reference.
 * @param key        Attribute of keyset.
 * @param attr       Attribute type.
 * @param rec        Recursive lookup is performed if true.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
static int
get_keyset_by_attr(service_Whois service,
		const char *key,
		ccReg_KeySetInvKeyType attr,
		int rec,
		general_object *objects,
		int *index_free, char *errmsg,
		char* reg_mojeid_handle)
{
	CORBA_Environment	 ev[1];
	ccReg_KeySetDetails	*c_keysets; /* keyset details */
	int	 retr;  /* retry counter */
	int	 i;
	int	 ret;

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call keyset method */
		c_keysets = ccReg_Whois_getKeySetsByInverseKey(
				(ccReg_Whois) service, key, attr,
				MAX_OBJECT_COUNT - *index_free, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
		return CORBA_SERVICE_FAILED;
	}
	CORBA_exception_free(ev);

	ret = CORBA_OK;
	/* copy all returned keysets */
	for (i = 0; i < c_keysets->_length && *index_free < MAX_OBJECT_COUNT; i++)
	{
		copy_keyset(&objects[(*index_free)++], &c_keysets->_buffer[i]);
		ret = recurse_keyset(service, rec,
				&objects[(*index_free) - 1].obj.k,
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK)
			break;
	}

	CORBA_free(c_keysets);

	return ret;
}

/**
 * Translate status ids by domain objects to appropriate strings.
 *
 * @param service     Whois corba object reference.
 * @param objects     Array of objects.
 * @param errmsg      Buffer for error message.
 * @return            Status.
 */
static int
translate_status(service_Whois service, general_object *objects, char *errmsg)
{
	int	 i, j, k;
	int	 retr;
	obj_domain	*d;
	CORBA_Environment	 ev[1];
	Registry_ObjectStatusDescSeq	*c_stat;

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev);
		CORBA_exception_init(ev);

		c_stat = ccReg_Whois_getDomainStatusDescList(
				(ccReg_Whois) service, "EN", ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}
	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
		return CORBA_SERVICE_FAILED;
	}
	CORBA_exception_free(ev);

	for (i = 0; i < MAX_OBJECT_COUNT && objects[i].type != T_NONE; i++) {

		if (objects[i].type != T_DOMAIN)
			continue;

		d = &objects[i].obj.d;
		for (j = 0; d->status_ids[j] != -1; j++) {
			for (k = 0; k < c_stat->_length; k++)
				if (d->status_ids[j] == c_stat->_buffer[k].id)
					break;
			if (k == c_stat->_length)
				d->status[j] = strdup("");
			else
				d->status[j] = strdup(c_stat->_buffer[k].name);
		}
		d->status[j] = NULL;
	}

	CORBA_free(c_stat);
	return CORBA_OK;
}

/**
 * Copy corba representation of domain object to our representation.
 *
 * @param obj         Field in object array which is destination of copy.
 * @param c_domain    Domain detail returned from CORBA.
 */
static void
copy_domain(general_object *obj, ccReg_DomainDetail *c_domain)
{
	obj_domain	*d;
	int	 i;

	/* copy domain data */
	obj->type = T_DOMAIN;
	d = &obj->obj.d;
	d->domain = NULL_STRDUP(c_domain->fqdn);
	if (*c_domain->valExDate == '\0')
		d->registrant = NULL_STRDUP(c_domain->registrantHandle);
	else
		d->registrant = NULL;
	d->nsset = NULL_STRDUP(c_domain->nssetHandle);
	d->keyset = NULL_STRDUP(c_domain->keysetHandle);
	d->registrar = NULL_STRDUP(c_domain->registrarHandle);
	d->registered = NULL_STRDUP(c_domain->createDate);
	d->changed = NULL_STRDUP(c_domain->updateDate);
	d->expire = NULL_STRDUP(c_domain->expirationDate);
	d->validated_to = NULL_STRDUP(c_domain->valExDate);
	d->admin_c = (char **)
		malloc((c_domain->admins._length + 1) * sizeof (char *));
	for (i = 0; i < c_domain->admins._length; i++)
		d->admin_c[i] = strdup(c_domain->admins._buffer[i]);
	d->admin_c[i] = NULL;
	d->temp_c = (char **)
		malloc((c_domain->temps._length + 1) * sizeof (char *));
	for (i = 0; i < c_domain->temps._length; i++)
		d->temp_c[i] = strdup(c_domain->temps._buffer[i]);
	d->temp_c[i] = NULL;
	/* status values will be translated later */
	d->status = (char **)
		malloc((c_domain->statusList._length + 1) * sizeof (char *));
	d->status[0] = NULL;
	d->status_ids = (int *)
		malloc((c_domain->statusList._length + 1) * sizeof (int));
	for (i = 0; i < c_domain->statusList._length; i++)
		d->status_ids[i] = c_domain->statusList._buffer[i];
	d->status_ids[i] = -1;
}

/**
 * The function does recursion on domain.
 *
 * @param service     Whois corba object reference.
 * @param rec         Recursive lookup is performed if true.
 * @param d           Domain object on which recursion is done.
 * @param objects     Array of results.
 * @param index_free  First free index in array of results.
 * @param errmsg      Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return            Status.
 */
static int
recurse_domain(service_Whois service, int rec, obj_domain *d,
		general_object *objects, int *index_free, char *errmsg,
		char* reg_mojeid_handle)
{
	int	 i, ret;

	if (*index_free >= MAX_OBJECT_COUNT)
		return CORBA_OK_LIMIT;
	if (!rec)
		return CORBA_OK;

	/* recursion on registrant */
	if (d->registrant != NULL) {
		ret = get_contact_by_handle(service, d->registrant,
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK) return ret;
	}

	if (*index_free >= MAX_OBJECT_COUNT)
		return CORBA_OK_LIMIT;

	/* recursion on admin_c */
	for (i = 0; d->admin_c[i] != NULL; i++) {
		ret = get_contact_by_handle(service, d->admin_c[i],
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK) return ret;
	}

	if (*index_free >= MAX_OBJECT_COUNT)
		return CORBA_OK_LIMIT;

	/* recursion on temp_c */
	for (i = 0; d->temp_c[i] != NULL; i++) {
		ret = get_contact_by_handle(service, d->temp_c[i],
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK) return ret;
	}

	if (*index_free >= MAX_OBJECT_COUNT)
		return CORBA_OK_LIMIT;

	/* recursion on nsset */
	if (d->nsset != NULL) {
		ret = get_nsset_by_handle(service, d->nsset, rec,
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK) return ret;
	}

	/* recursion on keyset */
	if (d->keyset != NULL) {
		ret = get_keyset_by_handle(service, d->keyset, rec,
				objects, index_free, errmsg, reg_mojeid_handle);
		if(ret != CORBA_OK) return ret;
	}

	return CORBA_OK;
}

/**
 * Search domain by fqdn and dependent objects if recursion is switched on. Supress duplicates in array of objects
 *
 * @param service    Whois CORBA object reference.
 * @param handle     Fqdn of domain.
 * @param rec        Recursive lookup is performed if true.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
static int
get_domain_by_handle(service_Whois service, const char *handle, int rec,
		general_object *objects, int *index_free, char *errmsg,
		char* reg_mojeid_handle)
{
	CORBA_Environment	 ev[1];
	ccReg_DomainDetail	*c_domain; /* domain detail */
	int	 retr;  /* retry counter */
	int	 ret;   /* return code used in some cases */

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call domain method */
		c_domain = ccReg_Whois_getDomainByFQDN((ccReg_Whois) service,
				handle, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		if (IS_OBJECT_NOT_FOUND(ev))
			ret = CORBA_OK;
		else {
			ret = CORBA_SERVICE_FAILED;
			strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
			errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		}
		CORBA_exception_free(ev);
		return ret;
	}
	CORBA_exception_free(ev);

	if(!check_duplicates(T_DOMAIN, c_domain->fqdn, objects, *index_free)) {
		copy_domain(&objects[*index_free], c_domain);
		(*index_free)++;
		CORBA_free(c_domain);
		return recurse_domain(service, rec, &objects[*index_free - 1].obj.d,
			objects, index_free, errmsg, reg_mojeid_handle);

	} else {

		CORBA_free(c_domain);
		return CORBA_OK;
	}

}

/**
 * Search domain by its attribute and dependent objects if recursion is
 * switched on.
 *
 * @param service    Whois CORBA object reference.
 * @param key        Attribute of domain.
 * @param attr       Attribute type.
 * @param rec        Recursive lookup is performed if true.
 * @param objects    Array of resulting objects.
 * @param index_free First free item in array of objects.
 * @param errmsg     Buffer for error message.
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
static int
get_domain_by_attr(service_Whois service,
		const char *key,
		ccReg_DomainInvKeyType attr,
		int rec,
		general_object *objects,
		int *index_free, char *errmsg,
		char* reg_mojeid_handle)
{
	CORBA_Environment	 ev[1];
	ccReg_DomainDetails	*c_domains; /* domain details */
	int	 retr;  /* retry counter */
	int	 i;
	int	 ret;

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call domain method */
		c_domains = ccReg_Whois_getDomainsByInverseKey(
				(ccReg_Whois) service, key, attr,
				MAX_OBJECT_COUNT - *index_free, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
		return CORBA_SERVICE_FAILED;
	}
	CORBA_exception_free(ev);

	ret = CORBA_OK;
	/* copy all returned domains */
	for (i = 0; i < c_domains->_length; i++) {
		copy_domain(&objects[(*index_free)++], &c_domains->_buffer[i]);
		ret = recurse_domain(service, rec,
				&objects[*index_free - 1].obj.d,
				objects, index_free, errmsg, reg_mojeid_handle);
		if (ret != CORBA_OK)
			break;
	}

	CORBA_free(c_domains);
	return ret;
}

/**
 * Log a new event using logging daemon
 *
 * @param service    Whois CORBA object reference.
 * @param sourceIP   IP of the host which sent the request.
 * @param content    Raw content of the message.
 * @param properties Custom properties parsed from the content
 * @param log_entry_id Output of ID from event logger
 * @param errmsg     Buffer for error message.
 * @return           Status.
 */
int
whois_log_new_message(service_Logger service,
		const char *sourceIP,
		const char *content,
		ccReg_RequestProperties *properties,
		ccReg_TID *log_entry_id,
		char *errmsg)
{
	CORBA_Environment	 ev[1];
	int	 retr;  /* retry counter */
	int	 ret;
        ccReg_ObjectReferences *objrefs = NULL;

	if(properties == NULL) {
		properties = ccReg_RequestProperties__alloc();
		if(properties == NULL) return CORBA_SERVICE_FAILED;

		properties->_maximum = properties->_length = 0;
	}

        if(objrefs == NULL) {
                objrefs = ccReg_ObjectReferences__alloc();
                if(objrefs == NULL) {
                        CORBA_free(properties);
			return CORBA_SERVICE_FAILED;
		}

                objrefs->_maximum = objrefs->_length = 0;
        }
 

    *log_entry_id = 0;
	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

		/* call logger method */

		*log_entry_id = ccReg_Logger_createRequest((ccReg_Logger) service, sourceIP,  LC_UNIX_WHOIS, content, properties, objrefs, Info, 0, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

        CORBA_free(properties);
        CORBA_free(objrefs);

        // TODO handle user-define exceptions from Logger.idl
	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
        *log_entry_id = 0;
		return CORBA_SERVICE_FAILED;
	}
	CORBA_exception_free(ev);

	return CORBA_OK;
}

/**
 * Update and close existing event using logging daemon
 *
 * @param service    Whois CORBA object reference.
 * @param content    Raw content of the message.
 * @param properties Custom properties parsed from the content
 * @param log_entry_id ID of the log entry to be close
 * @param errmsg     Buffer for error message.
 * @return           Status.
 */
int
whois_close_log_message(service_Logger service,
		const char *content,
		ccReg_RequestProperties *properties,
		ccReg_TID log_entry_id,
		CORBA_long result_code,
		char *errmsg)
{
	CORBA_Environment	 ev[1];
	int	 retr;  /* retry counter */
        ccReg_ObjectReferences *objrefs=NULL;

	// in this case request logging is practically turned of and if there should be an error message,
	// it was already generated before
	if(service == NULL || log_entry_id == 0) return CORBA_OK;	

	if(properties == NULL) {
		properties = ccReg_RequestProperties__alloc();
		if(properties == NULL) return CORBA_SERVICE_FAILED;

		properties->_maximum = properties->_length = 0;
	}

        if(objrefs == NULL) {
                objrefs = ccReg_ObjectReferences__alloc();
                if(objrefs == NULL) {
                        CORBA_free(properties);
			return CORBA_SERVICE_FAILED;
		}

                objrefs->_maximum = objrefs->_length = 0;
        }

	/* retry loop */
	for (retr = 0; retr < MAX_RETRIES; retr++) {
		if (retr != 0) CORBA_exception_free(ev); /* valid first time */
		CORBA_exception_init(ev);

                ccReg_Logger_closeRequest((ccReg_Logger) service, log_entry_id, content, properties, objrefs, result_code, 0, ev);

		/* if COMM_FAILURE is not raised then quit retry loop */
		if (!raised_exception(ev) || IS_NOT_COMM_FAILURE_EXCEPTION(ev))
			break;
		usleep(RETR_SLEEP);
	}

        CORBA_free(properties);
        CORBA_free(objrefs);

		// TODO handle exceptions ret = CORBA_UNKNOWN_ERROR;
	if (raised_exception(ev)) {
		strncpy(errmsg, ev->_id, MAX_ERROR_MSG_LEN - 1);
		errmsg[MAX_ERROR_MSG_LEN - 1] = '\0';
		CORBA_exception_free(ev);
		return CORBA_SERVICE_FAILED;
	}
	CORBA_exception_free(ev);

        return CORBA_OK;
}

/** Call the right function for the specific object type / search axis / handle
 * combination
 *
 * @param service    Whois CORBA object reference.
 * @param wr         Whois request.
 * @param objects    Array of resulting objects.
 * @param timebuf    Timestamp.
 * @param errmsg
 * @param reg_mojeid_handle    MojeID registrar handle.
 * @return           Status.
 */
int
whois_corba_call(service_Whois service, const whois_request *wr,
		general_object *objects, char *timebuf, char *errmsg,
		char* reg_mojeid_handle)
{
	int	rec = (wr->norecursion ? 0 : 1);
	int	ifree = 0;  /* Index of first free item in objects array */
	int	ret;        /* return code from subroutines */

	assert(timebuf != NULL);
	/* XXX Temporary hack */
	strncpy(timebuf, "DUMMY:TIME", TIME_BUFFER_LENGTH);

	switch (wr->axe) {
		case SA_REGISTRANT:
			ret = get_domain_by_attr(service, wr->value,
					ccReg_DIKT_REGISTRANT, rec, objects,
					&ifree, errmsg, reg_mojeid_handle);
			break;
		case SA_ADMIN_C:
			ret = get_domain_by_attr(service, wr->value,
					ccReg_DIKT_ADMIN, rec, objects,
					&ifree, errmsg, reg_mojeid_handle);
			break;
		case SA_TEMP_C:
			ret = get_domain_by_attr(service, wr->value,
					ccReg_DIKT_TEMP, rec, objects,
					&ifree, errmsg, reg_mojeid_handle);
			break;
		case SA_NSSET:
			ret = get_domain_by_attr(service, wr->value,
					ccReg_DIKT_NSSET, rec, objects,
					&ifree, errmsg, reg_mojeid_handle);
			break;
		case SA_NSERVER:
			ret = get_nsset_by_attr(service, wr->value,
					ccReg_NIKT_NS, rec, objects,
					&ifree, errmsg, reg_mojeid_handle);
			break;
		case SA_KEYSET:
			ret = get_domain_by_attr(service, wr->value,
 					ccReg_DIKT_KEYSET, rec, objects,
                    &ifree, errmsg, reg_mojeid_handle);
			break;
		case SA_TECH_C:
			// look for nsset by default
			if(wr->type & T_KEYSET && !(wr->type & T_NSSET)) {
				ret = get_keyset_by_attr(service, wr->value,
					ccReg_KIKT_TECH, rec, objects,
					&ifree, errmsg, reg_mojeid_handle);

			} else {
				ret = get_nsset_by_attr(service, wr->value,
					ccReg_NIKT_TECH, rec, objects,
					&ifree, errmsg, reg_mojeid_handle);
			}
			break;
		default:
			/* search by type */
			if (wr->type & T_DOMAIN) {
				ret = get_domain_by_handle(service, wr->value,
						rec, objects, &ifree, errmsg, reg_mojeid_handle);
				if (ret != CORBA_OK) goto search_end;
			}
			if (wr->type & T_NSSET) {
				ret = get_nsset_by_handle(service, wr->value,
						rec, objects, &ifree, errmsg, reg_mojeid_handle);
				if (ret != CORBA_OK) goto search_end;
			}
			if (wr->type & T_KEYSET) {
				ret = get_keyset_by_handle(service, wr->value,
						rec, objects, &ifree, errmsg, reg_mojeid_handle);
				if (ret != CORBA_OK) goto search_end;
			}
			if (wr->type & T_CONTACT) {
				ret = get_contact_by_handle(service, wr->value,
						objects, &ifree, errmsg, reg_mojeid_handle);
				if (ret != CORBA_OK) goto search_end;
			}
			if (wr->type & T_REGISTRAR) {
				ret = get_registrar_by_handle(service,wr->value,
						objects, &ifree, errmsg);
				if (ret != CORBA_OK) goto search_end;
			}
			ret = CORBA_OK;
			break;
	}

search_end:
	if (ifree < MAX_OBJECT_COUNT)
		objects[ifree].type = T_NONE;

	if (ret != CORBA_OK && ret != CORBA_OK_LIMIT)
		whois_release_data(objects);

	translate_status(service, objects, errmsg);
	return ret;
}

/** Release data of any of the objects
 * @param objects 	Object to release
 */
void
whois_release_data(general_object *objects)
{
	int	 i, j;
	obj_domain	*d;
	obj_nsset	*n;
	obj_keyset	*k;
	obj_contact	*c;
	obj_registrar	*r;

	keyset_dsrecord *ds;
	keyset_dnskey *dnsk;

	for (i = 0; (objects[i].type != T_NONE) && (i < MAX_OBJECT_COUNT); i++)
	{
		switch (objects[i].type) {
			case T_DOMAIN:
				d = &objects[i].obj.d;
				free(d->domain);
				free(d->registrant);
				for (j = 0; d->admin_c[j] != NULL; j++)
					free(d->admin_c[j]);
				free(d->admin_c);
				free(d->nsset);
				free(d->keyset);
				free(d->registrar);
				for (j = 0; d->status[j] != NULL; j++)
					free(d->status[j]);
				free(d->status);
				free(d->registered);
				free(d->changed);
				free(d->expire);
				free(d->validated_to);
				free(d->status_ids);
				break;
			case T_NSSET:
				n = &objects[i].obj.n;
				free(n->nsset);
				for (j = 0; n->nserver[j] != NULL; j++) {
					free(n->nserver[j]);
					free(n->nserver_addrs[j]);
				}
				free(n->nserver);
				free(n->nserver_addrs);
				for (j = 0; n->tech_c[j] != NULL; j++)
					free(n->tech_c[j]);
				free(n->tech_c);
				free(n->registrar);
				free(n->created);
				free(n->changed);
				break;
			case T_KEYSET:
				k = &objects[i].obj.k;
				// keyset handle
				free(k->keyset);

				// release DS records
				for(ds = k->ds; ds->digest != NULL; ds++) free(ds->digest);
				free(k->ds);

				// release dnskey records
				for(dnsk = k->keys; dnsk->public_key != NULL; dnsk++) free(dnsk->public_key);
				free(k->keys);

				for(j = 0; k->tech_c[j] != NULL; j++)
					free(k->tech_c[j]);

				free(k->tech_c);
				free(k->registrar);
				free(k->created);
				free(k->changed);
				break;
			case T_CONTACT:
				c = &objects[i].obj.c;
				free(c->contact);
                                if(c->disclose == 1) {
                                    free(c->org);
                                    free(c->name);
                                    for (j = 0; c->address[j] != NULL; j++)
                                            free(c->address[j]);
                                    free(c->address);
                                    free(c->phone);
                                    free(c->fax_no);
                                    free(c->e_mail);
                                    free(c->registrar);
                                    free(c->created);
                                    free(c->changed);
                                }
				break;
			case T_REGISTRAR:
				r = &objects[i].obj.r;
				free(r->registrar);
				free(r->org);
				free(r->url);
				free(r->phone);
				for (j = 0; r->address[j] != NULL; j++)
					free(r->address[j]);
				free(r->address);
				break;
			default:
				assert(1 == 3);
				break;
		}
	}
}
