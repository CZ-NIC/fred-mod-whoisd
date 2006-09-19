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
#define CORBA_OK	0 /**< No error occured. */
#define CORBA_SERVICE_FAILED	1 /**< Could not obtain object's reference. */
#define CORBA_INTERNAL_ERROR	2 /**< Internal error == malloc failed. */
#define CORBA_DOMAIN_FREE	3 /**< No info for domain. */
#define CORBA_DOMAIN_INVALID	4 /**< Invalid identificator of domain. */
#define CORBA_DOMAIN_LONG	5 /**< Domain name is too long. */
#define CORBA_DOMAIN_BAD_ZONE	6 /**< Domain is not in our zone. */
#define CORBA_UNKNOWN_ERROR	7 /**< Unknown error returned over CORBA. */
/**
 * @}
 */

/**
 * Structure used to hold global ORB's and object's reference.
 *
 * Member variables are kept private and are understandable only by CORBA
 * component.
 */
typedef struct whois_corba_globs_t whois_corba_globs;

/**
 * Status values for domain.
 */
typedef enum { DOMAIN_ACTIVE, DOMAIN_EXPIRED }domain_status;

/**
 * Structure holding domain data. Name is not included since it is known
 * by caller.
 */
typedef struct {
	char  *fqdn; /**< Name of a domain. */
	domain_status status; /**< Domain's status. */
	char  *created;  /**< Date a domain was created. */
	char  *expired;  /**< Expiration date of a domain. */
	char  *registrarName;/**< Name of company, which registered domain. */
	char  *registrarUrl; /**< URL of company, which registered domain. */
	int    ns_length; /**< Number of nameservers of a domain. */
	char **nameservers; /**< FQDNs of nameservers of a domain. */
	int    tech_length;   /**< Number of technical contacts for a domain. */
	char **techs;   /**< Handles of techical contacts for a domain. */
}whois_data_t;

/**
 * Initialization of global ORB and object's reference getting.
 *
 * Must be called before any other function from CORBA component.
 *
 * @param ns_host  Host and optionally port where nameservice runs.
 * @param obj_name Name under which is registered whois object by nameservice.
 * @return Pointer to struct containing global ORB and object's reference.
 */
whois_corba_globs *whois_corba_init(const char *ns_host, const char *obj_name);

/**
 * This cleanup routine releases global ORB and object's reference initialized
 * int whois_corba_init().
 *
 * @param globs CORBA data to be released.
 */
void whois_corba_init_cleanup(whois_corba_globs *globs);

/**
 * The core function of whois module performs actual query for domain.
 *
 * @param globs Data needed for CORBA call and initialized in whois_corba_init().
 * @param dname Domain name.
 * @param wd    Domain info struct holding output parameters from CORBA call.
 * @param timebuf Time of response generation (buffer must be preallocated).
 * @param timebuflen Length of buffer holding timestamp.
 * @return Status code.
 */
int
whois_corba_call(whois_corba_globs *globs,
		const char *dname,
		whois_data_t **wd,
		char *timebuf,
		unsigned timebuflen);

/**
 * Release content of whois_data_t structure.
 *
 * We don't want to mix apache pools with malloc and free routines within one
 * file, so we have to explicitly call this function in order to release whois
 * data returned from previous call. You must NOT pass NULL pointer as argument.
 *
 * @param wd Whois data to be freed.
 */
void whois_release_data(whois_data_t *wd);

#endif /* WHOIS_CLIENT_H */
