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
 * @file whois-client.h
 *
 * This file defines interface to CORBA backend.
 *
 * The program is divided into two parts. First contains apache stuff and
 * second implements CORBA calls to CORBA server, which are declared here.
 */
#ifndef WHOIS_CLIENT_H
#define WHOIS_CLIENT_H

/**
 * @defgroup corbastatgroup Definition of corba status codes.
 *
 * Theese are used in apache module to analyze what happened during corba call.
 * Appropriate apache log message is then generated if needed.
 *
 * @{
 */
#define CORBA_OK		0 /**< No error occured. */
/** No error, but limit on # of objects was reached. */
#define CORBA_OK_LIMIT		1
#define CORBA_SERVICE_FAILED	2 /**< Could not obtain object's reference. */
#define CORBA_INTERNAL_ERROR	3 /**< Internal error == malloc failed. */
#define CORBA_UNKNOWN_ERROR	4 /**< Unknown error returned over CORBA. */
/**
 * @}
 */

/**
 * Length of buffer used to hold time of response generation (must be enough
 * even for RFC822 date).
 */
#define TIME_BUFFER_LENGTH	60
/** Length of buffer used to hold error message from corba backend. */
#define MAX_ERROR_MSG_LEN	100
/**
 * Length of array for result objects and also a limit for maximal number
 * of objects returned by whois query.
 */
#define MAX_OBJECT_COUNT 100

typedef void *service_Whois;

#define T_NONE		0   /* Nothing. */
#define T_DOMAIN	1   /* Object type domain. */
#define T_NSSET		2   /* Object type nsset. */
#define T_CONTACT	4   /* Object type contact. */
#define T_REGISTRAR	8   /* Object type registrar. */
#define T_KEYSET	16  /* Object type keyset. */

/**
 * Axes used in reverse searches.
 */
typedef enum {
	SA_NONE = 0,
	SA_REGISTRANT,
	SA_ADMIN_C,
	SA_TEMP_C,
	SA_NSSET,
	SA_KEYSET,
	SA_NSERVER,
	SA_TECH_C
}search_axis;

/**
 * Whois request structure.
 */
typedef struct {
	search_axis	axe;
	int	 norecursion;
	int	 type;
	const char	*value;
}whois_request;

/** Structure holding domain data. */
typedef struct {
	char	 *domain;      /**< Domain name. */
	char	 *registrant;  /**< Registrant. */
	char	**admin_c;     /**< Administrators. */
	char	**temp_c;      /**< Temporary contacts. */
	char	 *nsset;       /**< Nsset handle. */
	char 	 *keyset;      /**< KeySet handle */
	char	 *registrar;   /**< Handle of registrar. */
	char	**status;      /**< Status array for domain. */
	char	 *registered;  /**< Date of domain registration. */
	char	 *changed;     /**< Last update of domain. */
	char	 *expire;      /**< Expiration date of domain. */
	char	 *validated_to;/**< Not NULL if it is an ENUM domain. */
	int	 *status_ids;  /**< Untranslated status numbers from corba. */
}obj_domain;

/** Structure holding nsset data. */
typedef struct {
	char	 *nsset;       /**< Handle of nsset. */
	char	**nserver;     /**< Nameservers in nsset. */
	char	**tech_c;      /**< Handles of techical contacts. */
	char	 *registrar;   /**< Handle of registrar. */
	char	 *created;     /**< Date of nsset creation. */
	char	 *changed;     /**< Last update of nsset. */
}obj_nsset;

/** Structure holding keyset data */
typedef struct {
	char 	*keyset;	/**< Handle of keyset. */
	
	char   **tech_c;	/**< Handles of technical contacts. */

	int	*key_tag;	/**< Key tag for DNSKEY RR (RFC 4043 for details) */
	int	*alg;		/**< Algorithm type */ 
	int 	*digest_type;	/**< Digest type (must be SHA-1) */
	char   **digest;	/**< Digests in Delegation Signer records */
	int	*max_sig_life;	/**< Signature expiration period */	
	
	char 	*registrar;	/**< Handle of registrar. */
	char 	*created;	/**< Date of keyset creation. */
	char 	*changed;	/**< Last update of keyset. */
} obj_keyset;

/** Structure holding contact data. */
typedef struct {
	char	 *contact;     /**< Handle of contact. */
	char	 *org;         /**< Organization name. */
	char     *name;        /**< Name of contact. */
	char	**address;     /**< Address information. */
	char	 *phone;       /**< Phone number. */
	char	 *fax_no;      /**< Fax number. */
	char	 *e_mail;      /**< Email. */
	char	 *registrar;   /**< Handle of registrar. */
	char	 *created;     /**< Date of contact creation. */
	char	 *changed;     /**< Last update of contact. */
}obj_contact;

/** Structure holding registrar data. */
typedef struct {
	char	 *registrar;   /**< Handle of registrar. */
	char	 *org;         /**< Organization. */
	char     *url;         /**< URL of registrar's web pages. */
	char	 *phone;       /**< Phone number. */
	char	**address;     /**< Address information. */
}obj_registrar;

/** Structure able to hold any of the four types of whois objects. */
typedef struct {
	int	 type;         /**< Object type number. */
	union {
		obj_domain	d;
		obj_nsset	n;
		obj_keyset	k;
		obj_contact	c;
		obj_registrar	r;
	}obj;
}general_object;

/**
 * The core function of whois module performs actual query.
 *
 * @param service     Corba reference of remote whois object.
 * @param wr          Representation of whois request.
 * @param objects     List of objects to be printed.
 * @param timebuf     Time of response generation (buffer must be
 *                    TIME_BUFFER_LENGTH bytes long).
 * @param errmsg      Buffer for error message.
 * @return            Status code.
 */
int
whois_corba_call(service_Whois service,
		const whois_request *wr,
		general_object *objects,
		char *timebuf,
		char *errmsg);

/**
 * Release content of whois_data_t structure.
 *
 * We don't want to mix apache pools with malloc and free routines within one
 * file, so we have to explicitly call this function in order to release whois
 * data returned from previous call. You must NOT pass NULL pointer as argument.
 *
 * @param wd Whois data to be freed.
 */
void whois_release_data(general_object *object_list);

#endif /* WHOIS_CLIENT_H */
