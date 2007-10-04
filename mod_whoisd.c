/**
 * @file mod_whoisd.c
 *
 * Module implementing whois service.
 *
 * Whois daemon accepts requests containing object name and returns information
 * about that object. The only object, which this server serves information
 * about, is currently a domain.
 *
 * The module serves only as a proxy, translating whois requests to CORBA
 * requests and back. CORBA functionality is implemented in whois-client.c.
 */

#include "httpd.h"

#include "http_log.h"
#define CORE_PRIVATE
#include "http_config.h"
#include "http_connection.h"	/* connection hooks */
#undef CORE_PRIVATE

#include "apr.h"
#include "apr_buckets.h"
#include "apr_file_io.h"
#include "apr_general.h"

#include "apr_file_io.h"
#ifndef APR_FOPEN_READ
#define APR_FOPEN_READ	APR_READ
#endif

#include "apr_lib.h"	/* apr_isdigit() */
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "apr_hash.h"
#include "apr_getopt.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "scoreboard.h"
#include "util_filter.h"

/* CORBA backend */
#include "whois-client.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/** This default disclaimer should never be used in production release. */
#define DEFAULT_DISCLAIMER	"Domain Information over Whois protocol\n"
/**
 * Message displayed bellow disclaimer when query cannot be answered
 * becauseof an error.
 */
#define INT_ERROR_MSG	"Internal error occured when processing your \
request.\nPlease try again later.\n"

#define MAXARGS	20  /**< Maximal number of whois arguments. */
#define MAXTYPELEN	15  /**< Maximal length of object type identifier. */
#define MAXAXELEN	15  /**< Maximal length of search axe identifier. */
#define MAXQPARLEN	15  /**< Maximal length of -q parameter. */
#define MIN_WHOIS_REQUEST_LENGTH 1    /**< Minimal length of input line. */
#define MAX_WHOIS_REQUEST_LENGTH 1000 /**< Maximal length of input line. */

module AP_MODULE_DECLARE_DATA whoisd_module; /**< Whois module declaration. */

/**
 * Configuration structure of whoisd module.
 */
typedef struct {
	int	 whoisd_enabled;         /**< Enabled/disabled flag. */
	const char *disclaimer_filename; /**< File with disclaimer. */
	char	*disclaimer;             /**< Disclaimer as a string. */
	char	*object;                 /**< Name of whois object. */
}whoisd_server_conf;

#if AP_SERVER_MINORVERSION_NUMBER == 0
/**
 * This is wrapper function for compatibility reason. Apache 2.0 does
 * not have ap_log_cerror, instead we will use ap_log_error.
 */
#define ap_log_cerror(mark, level, status, c, ...) \
	ap_log_error(mark, level, status, (c)->base_server, __VA_ARGS__)
#endif


#define IS_SEARCH_SET(wr)   ((wr)->axe || (wr)->norecursion || (wr)->type)

static const char *usagestr = \
"% Usage:   whois [options] [[type] value]\n\
% \n\
% Options:\n\
%   -r       Switch off recursion. Only the object which is primary target\n\
%            of query is returned.\n\
%   -T type  Type of object to lookup (domain, nsset, contact, registrar).\n\
%            There may be more types separated by comma without spaces\n\
%            between them. The types are case-insensitive.\n\
%   -i attr  Lookup object by its attribute. Attribute can be any of\n\
%            attributes from object templates marked by flag \"inverse key\".\n\
%            Attribute name is case-insensitive.\n\
%   -q version    Returns version of whois server.\n\
%   -q indexes    Returns list of attributes which can be used in search. The\n\
%                 attributes have form object:attribute.\n\
%   -q templates  Returns templates for all four object types.\n\
% \n\
% There's yet another way how to specify a type of object to lookup. Just\n\
% prefix the object's identifier with the name of a type. The following two\n\
% examples are equivalent:\n\
% \n\
%  $ whois -T domain nic.cz\n\
% \n\
%  $ whois \"domain nic.cz\"\n\
% \n\
% The -q parameter can be used only once and not in combination with any\n\
% other option. The -i parameter can be used only once.\n\
% \n\
% More information about this implementation of whois server can be found at\n\
% http://www.lammer.cz/\n\
";

static const char *indexlist = \
"% The folowing object types can be looked up in whois database:\n\
%    domain, nsset, contact, registrar.\n\
% \n\
% If you don't specify -i option the object is looked up by its primary key.\n\
% Specify object type by -T option, if you want to narrow the search.\n\
% \n\
% List of attribute names which can be used with -i option. Use only the part\n\
% following the colon. The part preceeding the colon is object type, which is\n\
% associated with the attribute.\n\
% \n\
% domain:registrant\n\
% domain:admin-c\n\
% domain:temp-c\n\
% domain:nsset\n\
% nsset:nserver\n\
% nsset:tech-c\n\
";

static const char *templatelist = \
"% Object type templates are listed in following order:\n\
%     domain, nsset, contact, registrar.\n\
\n\
domain:       [mandatory]  [single]\n\
registrant:   [optional]   [single]\n\
admin-c:      [optional]   [multiple]\n\
temp-c:       [optional]   [multiple]\n\
nsset:        [optional]   [single]\n\
registrar:    [mandatory]  [single]\n\
status:       [optional]   [multiple]\n\
registered:   [mandatory]  [single]\n\
changed:      [optional]   [single]\n\
expire:       [mandatory]  [single]\n\
validated-to: [optional]   [single]\n\
\n\
nsset:        [mandatory]  [single]\n\
nserver:      [mandatory]  [multiple]\n\
tech-c:       [mandatory]  [multiple]\n\
registrar:    [mandatory]  [single]\n\
created:      [mandatory]  [single]\n\
changed:      [optional]   [single]\n\
\n\
contact:      [mandatory]  [single]\n\
org:          [optional]   [single]\n\
name:         [mandatory]  [single]\n\
address:      [mandatory]  [multiple]\n\
phone:        [optional]   [single]\n\
fax-no:       [optional]   [single]\n\
e-mail:       [mandatory]  [single]  [hidable]\n\
registrar:    [mandatory]  [single]\n\
created:      [mandatory]  [single]\n\
changed:      [optional]   [single]\n\
\n\
registrar:    [mandatory]  [single]\n\
org:          [mandatory]  [single]\n\
url:          [mandatory]  [single]\n\
phone:        [optional]   [single]\n\
address:      [mandatory]  [multiple]\n\
";

static void print_intro(apr_bucket_brigade *bb, conn_rec *c,
		const char *disclaimer, const char *timestamp)
{
	int	pending_comment; /* pending nl from previous bucket (boolean) */
	apr_bucket	*b;      /* used for escaping of disclaimer */
	apr_status_t	 status;

	/*
	 * Print disclaimer into bucket, note that this disclaimer is not
	 * properly escaped yet. Escaping is done bellow in 'for' loop.
	 */
	apr_brigade_puts(bb, NULL, NULL, disclaimer);
	apr_brigade_printf(bb, NULL, NULL, "\nWhoisd Server Version: %s\n",
			PACKAGE_VERSION);
	if (timestamp != NULL)
		apr_brigade_printf(bb, NULL, NULL,"Timestamp: %s\n", timestamp);

	/*
	 * Every line which doesn't contain actual data must be preceeded by
	 * comment sign ('%').
	 * Everything above is printed in a single bucket, nevertheless we
	 * iterate through all buckets from brigade. That's less error prone,
	 * because our assumption about one bucket might not hold forever.
	 */
	pending_comment = 1;
	for (b  = APR_BRIGADE_FIRST(bb);
		 b != APR_BRIGADE_SENTINEL(bb);
		 b  = APR_BUCKET_NEXT(b))
	{
		const char	*str, *pos;
		apr_size_t	 len;
		apr_bucket	*bnew;

		/*
		 * if we have found nl at the end of previous bucket, insert
		 * comment sign before current bucket.
		 */
		if (pending_comment) {
			bnew = apr_bucket_heap_create("% ", 2, NULL,
					c->bucket_alloc);
			APR_BUCKET_INSERT_BEFORE(b, bnew);
			pending_comment = 0;
		}

		status = apr_bucket_read(b, &str, &len, APR_NONBLOCK_READ);
		if (status != APR_SUCCESS)
			/* ignore the error and return */
			return;

		/* while there is a match */
		if ((pos = memchr(str, APR_ASCII_LF, len)) != NULL) {
			/*
			 * if ln is last char in bucket, don't split the bucket
			 * and defer comment insertion.
			 */
			if (pos - str == len - 1) {
				pending_comment = 1;
			}
			else {
				apr_bucket_split(b, pos - str + 1);
				bnew = apr_bucket_heap_create("% ", 2, NULL,
						c->bucket_alloc);
				APR_BUCKET_INSERT_AFTER(b, bnew);
				b = bnew; /* move one bucket ahead */
			}
		}
	}
	/* this new line will not be escaped */
	apr_brigade_puts(bb, NULL, NULL, "\n");
}

/**
 * Routine trigerred upon error.
 *
 * @param c            Connection.
 * @param disclaimer   Disclaimer.
 * @param nerr         Number of error.
 */
static void send_error(conn_rec *c, const char *disclaimer, int nerr)
{
	apr_bucket_brigade	*bb;
	apr_status_t	 status;

	bb = apr_brigade_create(c->pool, c->bucket_alloc);
	print_intro(bb, c, disclaimer, NULL);

	switch (nerr) {
	case 101:
		apr_brigade_puts(bb, NULL, NULL,
"%ERROR:101: no entries found\n"
"% \n"
"% No entries found.");
		break;
	case 107:
		apr_brigade_puts(bb, NULL, NULL, usagestr);
		apr_brigade_puts(bb, NULL, NULL, "\n");
		apr_brigade_puts(bb, NULL, NULL,
"%ERROR:107: usage error\n"
"% \n"
"% Unknown option, invalid combination of options, invalid value for option\n"
"% or invalid count of parameters was specified.");
		break;
	case 108:
		apr_brigade_puts(bb, NULL, NULL,
"%ERROR:108: invalid request\n"
"% \n"
"% Invalid character in request, request not properly terminated or too long.");
		break;
	case 501:
		apr_brigade_puts(bb, NULL, NULL,
"%ERROR:501: internal server error\n"
"% \n"
"% Query didn't succeed becauseof server-side error. Please try again later.");
		break;
	default:
		break;
	}
	apr_brigade_puts(bb, NULL, NULL, "\n\n\n");

	/* ok, finish it - flush what we have produced so far */
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(c->bucket_alloc));

	status = ap_fflush(c->output_filters, bb);
	if (status != APR_SUCCESS)
		  ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				  "Error when sending response");
}

/**
 * Function prints domain information to bucket brigade.
 *
 * @param bb    Bucket brigade.
 * @param d     Domain object.
 */
static void print_domain_object(apr_bucket_brigade *bb, obj_domain *d)
{
	int	i;

#define SAFE_PRINTF(fmt, str) \
	if (str != NULL) apr_brigade_printf(bb, NULL, NULL, fmt, str);

	SAFE_PRINTF("domain:       %s\n", d->domain);
	SAFE_PRINTF("registrant:   %s\n", d->registrant);
	for (i = 0; d->admin_c[i] != NULL; i++) {
	SAFE_PRINTF("admin-c:      %s\n", d->admin_c[i]);
	}
	for (i = 0; d->temp_c[i] != NULL; i++) {
	SAFE_PRINTF("temp-c:       %s\n", d->temp_c[i]);
	}
	SAFE_PRINTF("nsset:        %s\n", d->nsset);
	SAFE_PRINTF("registrar:    %s\n", d->registrar);
	if (d->status[0] == NULL) {
	SAFE_PRINTF("status:       %s\n", "paid and in zone");
	}
	for (i = 0; d->status[i] != NULL; i++) {
	SAFE_PRINTF("status:       %s\n", d->status[i]);
	}
	SAFE_PRINTF("registered:   %s\n", d->registered);
	SAFE_PRINTF("changed:      %s\n", d->changed);
	SAFE_PRINTF("expire:       %s\n", d->expire);
	SAFE_PRINTF("validated-to: %s\n", d->validated_to);
	apr_brigade_puts(bb, NULL, NULL, "\n");

#undef SAFE_PRINTF
}

/**
 * Function prints nsset information to bucket brigade.
 *
 * @param bb    Bucket brigade.
 * @param n     Nsset object.
 */
static void print_nsset_object(apr_bucket_brigade *bb, obj_nsset *n)
{
	int	i;

#define SAFE_PRINTF(fmt, str) \
	if (str != NULL) apr_brigade_printf(bb, NULL, NULL, fmt, str);

	SAFE_PRINTF("nsset:        %s\n", n->nsset);
	for (i = 0; n->nserver[i] != NULL; i++) {
	SAFE_PRINTF("nserver:      %s\n", n->nserver[i]);
	}
	for (i = 0; n->tech_c[i] != NULL; i++) {
	SAFE_PRINTF("tech-c:       %s\n", n->tech_c[i]);
	}
	SAFE_PRINTF("registrar:    %s\n", n->registrar);
	SAFE_PRINTF("created:      %s\n", n->created);
	SAFE_PRINTF("changed:      %s\n", n->changed);
	apr_brigade_puts(bb, NULL, NULL, "\n");

#undef SAFE_PRINTF
}

/**
 * Function prints contact information to bucket brigade.
 *
 * @param bb    Bucket brigade.
 * @param c     Contact object.
 */
static void print_contact_object(apr_bucket_brigade *bb, obj_contact *c)
{
	int	i;

#define SAFE_PRINTF(fmt, str) \
	if (str != NULL) apr_brigade_printf(bb, NULL, NULL, fmt, str);

	SAFE_PRINTF("contact:      %s\n", c->contact);
	SAFE_PRINTF("org:          %s\n", c->org);
	SAFE_PRINTF("name:         %s\n", c->name);
	for (i = 0; c->address[i] != NULL; i++) {
	SAFE_PRINTF("address:      %s\n", c->address[i]);
	}
	SAFE_PRINTF("phone:        %s\n", c->phone);
	SAFE_PRINTF("fax-no:       %s\n", c->fax_no);
	SAFE_PRINTF("e-mail:       %s\n", c->e_mail);
	SAFE_PRINTF("registrar:    %s\n", c->registrar);
	SAFE_PRINTF("created:      %s\n", c->created);
	SAFE_PRINTF("changed:      %s\n", c->changed);
	apr_brigade_puts(bb, NULL, NULL, "\n");

#undef SAFE_PRINTF
}

/**
 * Function prints registrar information to bucket brigade.
 *
 * @param bb    Bucket brigade.
 * @param r     Registrar object.
 */
static void print_registrar_object(apr_bucket_brigade *bb, obj_registrar *r)
{
	int	i;

#define SAFE_PRINTF(fmt, str) \
	if (str != NULL) apr_brigade_printf(bb, NULL, NULL, fmt, str);

	SAFE_PRINTF("registrar:    %s\n", r->registrar);
	SAFE_PRINTF("org:          %s\n", r->org);
	SAFE_PRINTF("url:          %s\n", r->url);
	SAFE_PRINTF("phone:        %s\n", r->phone);
	for (i = 0; r->address[i] != NULL; i++) {
	SAFE_PRINTF("address:      %s\n", r->address[i]);
	}
	apr_brigade_puts(bb, NULL, NULL, "\n");

#undef SAFE_PRINTF
}

/**
 * Whois request processor.
 *
 * This function is called from connection handler. It performs
 * a CORBA call through CORBA backend and then processes data and
 * sends a whois answer.
 *
 * @param c   Connection.
 * @param sc  Server configuration.
 * @return    Result of processing.
 */
static apr_status_t process_whois_query(conn_rec *c, whoisd_server_conf *sc,
		whois_request *wr)
{
	int	rc;
	int	i;
	char	timebuf[TIME_BUFFER_LENGTH]; /* buffer for time of resp. gen. */
	char	errmsg[MAX_ERROR_MSG_LEN];
	general_object	*objects; /* result array */
	apr_time_t	 time1, time2; /* meassuring of CORBA server latency */
	apr_status_t	 status;
	apr_bucket_brigade *bb;  /* brigade for response */
	service_Whois	 service;
	apr_hash_t	*references;
	module		*corba_module;

	/*
	 * get module structure for mod_corba, in order to retrieve service
	 * stored by that module in connection config.
	 */
	corba_module = NULL;
	for (i = 0; ap_loaded_modules[i] != NULL; i++)
		if (!strcmp(ap_loaded_modules[i]->name, "mod_corba.c")) {
			corba_module = ap_loaded_modules[i];
			break;
		}

	if (corba_module == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"mod_corba module was not loaded - unable to "
				"handle a whois request");
		return APR_EGENERAL;
	}

	references = (apr_hash_t *)
		ap_get_module_config(c->conn_config, corba_module);
	if (references == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
			"mod_corba is not enabled for this server though it "
			"should be! Cannot handle whois request.");
		return APR_EGENERAL;
	}

	service = (service_Whois *) apr_hash_get(references, sc->object,
			strlen(sc->object));
	if (service == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
			"Could not obtain object reference for alias '%s'. "
			"Check mod_corba's configuration.", sc->object);
		return APR_EGENERAL;
	}

	objects = (general_object *)
		apr_palloc(c->pool, MAX_OBJECT_COUNT * (sizeof *objects));
	errmsg[0] = '\0';
	/* We will meassure the time the corba function call takes. */
	time1 = apr_time_now();
	rc = whois_corba_call(service, wr, objects, timebuf, errmsg);
	time2 = apr_time_now();

	ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c,
			"Request for \"%s\" processed in %u ms",
			wr->value, (unsigned int) (time2 - time1) / 1000);

	/*
	 * XXX Until we will decide if the timestamp should be generated
	 * in CORBA server, it is generated here (and anything returned from
	 * whois-client.c is overwritten).
	 */
	apr_ctime(timebuf, time1);

	if (rc == CORBA_SERVICE_FAILED) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
			"CORBA service failed: %s", errmsg);
		send_error(c, sc->disclaimer, 501);
		return APR_SUCCESS;
	}
	else if (rc == CORBA_INTERNAL_ERROR) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
			"Internal error in CORBA backend: %s", errmsg);
		send_error(c, sc->disclaimer, 501);
		return APR_SUCCESS;
	}
	else if (rc != CORBA_OK && rc != CORBA_OK_LIMIT) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
			"Unknown error in CORBA backend (%d): %s",
			rc, errmsg);
		send_error(c, sc->disclaimer, 501);
		return APR_SUCCESS;
	}

	/* check if at least one object was found */
	if (objects[0].type == T_NONE) {
		ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,"No entries found");
		send_error(c, sc->disclaimer, 101);
		return APR_SUCCESS;
	}

	/* this brigade is used for response */
	bb = apr_brigade_create(c->pool, c->bucket_alloc);
	print_intro(bb, c, sc->disclaimer, timebuf);

	if (rc == CORBA_OK_LIMIT) {
		apr_brigade_puts(bb, NULL, NULL,
"% The list of objects is not complete! It was truncated, because it was\n"
"% too long.\n\n");
	}

	for (i = 0; (i < MAX_OBJECT_COUNT) && (objects[i].type != T_NONE); i++)
	{
		switch (objects[i].type) {
			case T_DOMAIN:
				print_domain_object(bb, &objects[i].obj.d);
				break;
			case T_NSSET:
				print_nsset_object(bb, &objects[i].obj.n);
				break;
			case T_CONTACT:
				print_contact_object(bb, &objects[i].obj.c);
				break;
			case T_REGISTRAR:
				print_registrar_object(bb, &objects[i].obj.r);
				break;
			default:
				break;
		}
	}
	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"%d object(s) returned for query", i);
	whois_release_data(objects);

	apr_brigade_puts(bb, NULL, NULL, "\n");

	/* ok, finish it - flush what we have produced so far */
	APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(c->bucket_alloc));
	status = ap_fflush(c->output_filters, bb);
	if (status != APR_SUCCESS) {
		  ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				  "Error when sending response");
		  return APR_EGENERAL;
	}

	return APR_SUCCESS;
}

/**
 * This will read whois request (one line of text).
 *
 * @param c     Connection structure.
 * @param len   Length of request.
 * @return      The string which was read, NULL in case of error.
 */
static char *read_request(conn_rec *c, int *http_status)
{
	char	*buf;   /* buffer for user request */
	int	 i;
	apr_size_t	 len;   /* length of request */
	apr_bucket_brigade *bb;
	apr_status_t	status;

	bb = apr_brigade_create(c->pool, c->bucket_alloc);

	/*
	 * blocking read of one line of text.
	 * XXX Last argument seems to be ignored by ap_get_brigade when
	 * reading one line (it should be max number of bytes to read)
	 */
	status = ap_get_brigade(c->input_filters, bb, AP_MODE_GETLINE,
			APR_BLOCK_READ, 0);
	if (status != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Error when reading request");
		*http_status = HTTP_INTERNAL_SERVER_ERROR;
		return NULL;
	}

	buf = apr_palloc(c->pool, MAX_WHOIS_REQUEST_LENGTH + 1);
	if (buf == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Could allocate buffer for request.");
		*http_status = HTTP_INTERNAL_SERVER_ERROR;
		return NULL;
	}

	/* convert brigade into string */
	len = MAX_WHOIS_REQUEST_LENGTH;
	status = apr_brigade_flatten(bb, buf, &len);
	if (status != APR_SUCCESS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
				"Could not flatten apr_brigade!");
		*http_status = HTTP_INTERNAL_SERVER_ERROR;
		return NULL;
	}

	/* check if request isn't too long or too short (2=<CR><LF>) */
	if (len > MAX_WHOIS_REQUEST_LENGTH || len < MIN_WHOIS_REQUEST_LENGTH + 2)
	{
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Invalid length of request (%u bytes)",
				(unsigned) len);
		*http_status = HTTP_BAD_REQUEST;
		return NULL;
	}

	/*
	 * each request has to be terminated by <CR><LF>, apr_get_brigade
	 * returns whatever text is available, so we have to explicitly check
	 * for it.
	 */
	if (buf[len - 1] != APR_ASCII_LF || buf[len - 2] != APR_ASCII_CR) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Request is not terminated by <CR><LF>");
		*http_status = HTTP_BAD_REQUEST;
		return NULL;
	}
	/* strip <CR><LF> characters and NULL terminate request */
	len -= 2;
	buf[len] = '\0';

	/*
	 * Check each character of request that it is from subset of ASCII
	 */
	for (i = 0; i < len; i++) {
		/* 32 = space, 126 = ~ */
		if (buf[i] < 32 || buf[i] > 126)
			break;
	}
	if (i < len) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Invalid character in request (code = %u)",
				buf[i]);
		*http_status = HTTP_BAD_REQUEST;
		return NULL;
	}

	return buf;
}

/**
 * Function converts object type from string form to bit form. If the object
 * type is not recognized the bit array is unchanged.
 *
 * @param bittype   Number where each object type has its own bit.
 * @param strtype   Object type token.
 * @return          0 if successfull, 1 if object type was not recognized.
 */
static int getobjtype(int *bittype, const char *strtype)
{
	if (strncasecmp(strtype, "domain", MAXTYPELEN) == 0) {
		*bittype |= T_DOMAIN;
		return 0;
	}
	else if (strncasecmp(strtype, "nsset", MAXTYPELEN) == 0) {
		*bittype |= T_NSSET;
		return 0;
	}
	else if (strncasecmp(strtype, "contact", MAXTYPELEN) == 0) {
		*bittype |= T_CONTACT;
		return 0;
	}
	else if (strncasecmp(strtype, "registrar", MAXTYPELEN) == 0) {
		*bittype |= T_REGISTRAR;
		return 0;
	}
	/* unknown object type */
	return 1;
}

/**
 * Connection handler of mod_whoisd module.
 *
 * If mod_whoisd is for server enabled, the request is read (assuming
 * it is whois request) and processed in request handler, which is called
 * from inside of this function.
 *
 * @param c   Incomming connection.
 * @return    Status.
 */
static int process_whois_connection(conn_rec *c)
{
	apr_status_t	 status;
	apr_getopt_t	*os;     /* options structure */
	char	*inputline;      /* input line read from socket */
	const char	*argv[MAXARGS]; /* array of whois arguments */
	char	*lasts;          /* auxiliary argument for strtok_r */
	char	 optch;          /* option character */
	const char	*optarg; /* option argument */
	char	*p;
	int	 argc;           /* option count */
	int	 q_version;	 /* query version */
	int	 q_indexes;	 /* query indexes */
	int	 q_templates;	 /* query templates */
	int	 http_status;    /* used in read_request */
	int	 parse_error;    /* error when parsing options */
	whois_request	*wr;     /* whois request structure */
	server_rec	*s = c->base_server;
	whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);

	/* do nothing if whoisd is disabled */
	if (!sc->whoisd_enabled)
		return DECLINED;

	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"whois connection handler enabled");
	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);

	/* add connection output filters */
	ap_add_output_filter("WHOIS_OUTPUT_FILTER", NULL, NULL, c);

	/* read request */
	inputline = read_request(c, &http_status);
	if (inputline == NULL) {
		if (http_status == HTTP_BAD_REQUEST)
			send_error(c, sc->disclaimer, 108);
		else
			send_error(c, sc->disclaimer, 501);
		return http_status;
	}

	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"Whois input line: %s", inputline);

	/* break input line in tokens */
	for (argc = 1, p = strtok_r(inputline, " \t", &lasts); p;
			p = strtok_r(NULL, " \t", &lasts), argc++)
	{
		if (argc == MAXARGS)
			break;
		argv[argc] = p;
	}
	if (argc == MAXARGS) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Maximal allowed number of args exceeded.");
		send_error(c, sc->disclaimer, 107);
		return HTTP_BAD_REQUEST;
	}
	argv[0] = NULL; /* command name - never used */
	argv[argc] = NULL;

	/* parse options */
	wr = (whois_request *) apr_pcalloc(c->pool, sizeof(*wr));
	apr_getopt_init(&os, c->pool, argc, (const char * const *) argv);
	parse_error = q_version = q_indexes = q_templates = 0;
	while (!parse_error && (status = apr_getopt(os, "rT:i:q:", &optch, &optarg)) == APR_SUCCESS)
	{
		ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
				"Option #%d is %c with arg %s", os->ind, optch,
				(optarg == NULL) ? "None" : optarg);
		switch (optch) {
			case 'r':
				if (q_version || q_indexes || q_templates)
					parse_error = 1;
				else
					wr->norecursion = 1;
				break;
			case 'T':
				if (q_version || q_indexes || q_templates) {
					parse_error = 1;
					break;
				}
				if (getobjtype(&wr->type, optarg))
					parse_error = 1;
				break;
			case 'i':
				if (q_version || q_indexes || q_templates ||
						wr->axe)
				{
					parse_error = 1;
					break;
				}
				if (strncasecmp(optarg, "registrant",
							MAXAXELEN) == 0)
					wr->axe = SA_REGISTRANT;
				else if (strncasecmp(optarg, "admin-c",
							MAXAXELEN) == 0)
					wr->axe = SA_ADMIN_C;
				else if (strncasecmp(optarg, "temp-c",
							MAXAXELEN) == 0)
					wr->axe = SA_TEMP_C;
				else if (strncasecmp(optarg, "nsset",
							MAXAXELEN) == 0)
					wr->axe = SA_NSSET;
				else if (strncasecmp(optarg, "nserver",
							MAXAXELEN) == 0)
					wr->axe = SA_NSERVER;
				else if (strncasecmp(optarg, "tech-c",
							MAXAXELEN) == 0)
					wr->axe = SA_TECH_C;
				else
					parse_error = 1;
				break;
			case 'q':
				if (q_version || q_indexes || q_templates ||
						IS_SEARCH_SET(wr))
				{
					parse_error = 1;
					break;
				}
				if (strncmp(optarg, "version", MAXQPARLEN) == 0)
					q_version = 1;
				else if (strncmp(optarg, "indexes",
							MAXQPARLEN) == 0)
					q_indexes = 1;
				else if (strncmp(optarg, "templates",
							MAXQPARLEN) == 0)
					q_templates = 1;
				else
					parse_error = 1;
				break;
			default:
				parse_error = 1;
				break;
		}
	}

	if (parse_error || status != APR_EOF) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Error when parsing whois options.");
		send_error(c, sc->disclaimer, 107);
		return HTTP_BAD_REQUEST;
	}
	argc -= os->ind;
	/* check too many keywords case */
	if (argc > 2) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
			"Whois usage error: Too many search keys.");
		send_error(c, sc->disclaimer, 107);
		return HTTP_BAD_REQUEST;
	}
	/* check for query options */
	if (argc == 0) {
		apr_bucket_brigade *bb;

		if (!q_version && !q_indexes && !q_templates) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Whois usage error: "
				"Missing query option or search key.");
			send_error(c, sc->disclaimer, 107);
			return HTTP_BAD_REQUEST;
		}
		/* generate response */
		bb = apr_brigade_create(c->pool, c->bucket_alloc);
		print_intro(bb, c, sc->disclaimer, NULL);
		if (q_indexes) {
			ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
					"Query class: indexes query");
			apr_brigade_puts(bb, NULL, NULL, indexlist);
		}
		else if (q_templates) {
			ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
					"Query class: templates query");
			apr_brigade_puts(bb, NULL, NULL, templatelist);
		}
		else {
			ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
					"Query class: version query");
		}
		apr_brigade_puts(bb, NULL, NULL, "\n\n");

		/* ok, finish it - flush what we have produced so far */
		APR_BRIGADE_INSERT_TAIL(bb,
				apr_bucket_eos_create(c->bucket_alloc));
		status = ap_fflush(c->output_filters, bb);
		if (status != APR_SUCCESS) {
			  ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c,
					  "Error when sending response");
			  return HTTP_INTERNAL_SERVER_ERROR;
		}

		return OK;
	}

	if (q_version || q_indexes || q_templates) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
			"Whois usage error: "
			"Query option combined with search key.");
		send_error(c, sc->disclaimer, 107);
		return HTTP_BAD_REQUEST;
	}

	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"Query class: search query");

	/* parse the rest of query line */
	if (argc == 1)
		wr->value = argv[os->ind];
	else if (argc == 2) {
		if (getobjtype(&wr->type, argv[os->ind])) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Whois usage error: Unknown object type.");
			send_error(c, sc->disclaimer, 107);
			return HTTP_BAD_REQUEST;
		}
		wr->value = argv[os->ind + 1];
	}

	/* if type of object was not specified, all types should be searched */
	if (!wr->type)
		wr->type = (T_DOMAIN | T_NSSET | T_CONTACT | T_REGISTRAR);

	/* process request */
	status = process_whois_query(c, sc, wr);

	if (status != APR_SUCCESS)
		return HTTP_INTERNAL_SERVER_ERROR;

	return OK;
}

/**
 * Whois output filter inserts in front of every <LF>, which is not
 * preceeded by <CR>, <CR>.
 *
 * @param f    Chain of filters.
 * @param bb   Bucket brigade to be filtered.
 * @return     Status.
 */
static apr_status_t whois_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_bucket	*b, *bnew;
	apr_size_t	 len;
	apr_status_t	 status;
	const char	*str;
	char	*pos;

	for (b = APR_BRIGADE_FIRST(bb);
		 b != APR_BRIGADE_SENTINEL(bb);
		 b = APR_BUCKET_NEXT(b))
	{

		status = apr_bucket_read(b, &str, &len, APR_NONBLOCK_READ);

		if (status != APR_SUCCESS)
			return status;

		/*
		 * not all buckets contain string (for instance EOS and FLUSH
		 * don't).
		 */
		if (str == NULL) continue;

		/*
		 * while there is a match cut the bucket in 3 parts
		 * ... '\n' ...
		 * and insert <CR> where apropriate.
		 */
		if ((pos = memchr(str, APR_ASCII_LF, len)) != NULL) {
			if (pos == str) {
				bnew = apr_bucket_heap_create("\r", 1, NULL,
						f->c->bucket_alloc);
				APR_BUCKET_INSERT_BEFORE(b, bnew);
				if (len > 1)
					apr_bucket_split(b, 1);
			}
			else if (*(pos - 1) != APR_ASCII_CR) {
				apr_bucket_split(b, pos - str);
			}
		}
	}

	return ap_pass_brigade(f->next, bb);
}

/**
 * Postconfig hook is a good occasion to check consistency of mod_whoisd
 * configuration and to initialize CORBA component.
 *
 * @param p      Pool to allocate from.
 * @param plog   Pool used for logging.
 * @param ptemp  Temporary pool.
 * @param s      Server struct.
 * @return       Status.
 */
static int whois_postconfig_hook(apr_pool_t *p, apr_pool_t *plog,
		apr_pool_t *ptemp, server_rec *s)
{
	whoisd_server_conf *sc;

	/*
	 * Iterate through available servers and if whoisd is enabled
	 * do further checking
	 */
	while (s != NULL) {
		sc = (whoisd_server_conf *) ap_get_module_config(
				s->module_config, &whoisd_module);

		if (sc->whoisd_enabled) {
			if (sc->disclaimer_filename == NULL) {
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
					 "mod_whoisd: whoisd disclaimer not "
					 "set, using default.");
				sc->disclaimer = apr_pstrdup(p,
						DEFAULT_DISCLAIMER);
			}
			if (sc->object == NULL) {
				sc->object = apr_pstrdup(p, "Whois");
			}
		}
		/* get next virtual server */
		s = s->next;
	}
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
		 "mod_whoisd: Module successfully configured");

	return OK;
}

/**
 * Routine disables or enables the operation of mod_whois.
 *
 * @param cmd     Command.
 * @param dummy   Not used arg.
 * @param flag    The value.
 * @return        NULL if OK, otherwise a string.
 */
static const char *set_whois_protocol(cmd_parms *cmd, void *dummy, int flag)
{
	const char *err;
	server_rec *s = cmd->server;
	whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);
	
	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
	if (err) return err;

	sc->whoisd_enabled = flag;
	return NULL;
}

/**
 * Routine accepts name of file with disclaimer, it also reads the file
 * and stores disclaimer in server configuration struct.
 *
 * @param cmd     Command.
 * @param dummy   Not used arg.
 * @param a1      The value.
 * @return        NULL if OK, otherwise a string.
 */
static const char *set_disclaimer_file(cmd_parms *cmd, void *dummy,
		const char *a1)
{
	char	 buf[101];
	char	*res;
	const char	*err;
	apr_file_t	*f;
	apr_size_t	 nbytes;
	apr_status_t	 status;
	server_rec *s = cmd->server;
	whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) return err;

	/*
	 * catch double definition of filename
	 * that's not serious fault so we will just print log message
	 */
	if (sc->disclaimer_filename != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_whoisd: more than one definition of DisclaimerFile"
			". All but the first one will be ignored.");
		return NULL;
	}

	sc->disclaimer_filename = a1;

	/* open file */
	status = apr_file_open(&f, sc->disclaimer_filename, APR_FOPEN_READ,
			APR_OS_DEFAULT, cmd->temp_pool);
	if (status != APR_SUCCESS) {
		return apr_psprintf(cmd->temp_pool,
				"mod_whoisd: could not open disclaimer %s.",
				sc->disclaimer_filename);
	}

	/* read the file */
	res = apr_pstrdup(cmd->temp_pool, " ");
	nbytes = 100;
	while ((status = apr_file_read(f, (void *)buf, &nbytes)) == APR_SUCCESS)
	{
		buf[nbytes] = 0;
		res = apr_pstrcat(cmd->temp_pool, res, buf, NULL);
		nbytes = 100;
	}
	if (status != APR_EOF) {
		return apr_psprintf(cmd->temp_pool,
				"mod_whoisd: error when reading disclaimer %s.",
				sc->disclaimer_filename);
	}

	/* close the file */
	status = apr_file_close(f);
	if (status != APR_SUCCESS) {
		/*
		 * error when closing file. Eventhough it is not crucial error,
		 * we will rather quit and not continue in operation.
		 */
		return apr_psprintf(cmd->temp_pool,
				"mod_whoisd: error when closing disclaimer %s.",
				sc->disclaimer_filename);
	}

	sc->disclaimer = apr_pstrdup(cmd->pool, res);

	return NULL;
}

/**
 * Routine sets name under which is registered whois object by nameservice.
 *
 * @param cmd     Command.
 * @param dummy   Not used arg.
 * @param name    The value.
 * @return        NULL if OK, otherwise a string.
 */
static const char *set_whois_object(cmd_parms *cmd, void *dummy,
		const char *name)
{
	const char *err;
	server_rec *s = cmd->server;
	whoisd_server_conf *sc = (whoisd_server_conf *)
			ap_get_module_config(s->module_config, &whoisd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) return err;

	/*
	 * catch double definition of filename
	 * that's not serious fault so we will just print log message
	 */
	if (sc->object != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_whoisd: more than one definition of whois object "
			"name. All but the first one will be ignored");
		return NULL;
	}

	sc->object = apr_pstrdup(cmd->pool, name);

	return NULL;
}

/** Structure defining configuration options for whoisd module. */
static const command_rec whoisd_cmds[] = {
	AP_INIT_FLAG("WhoisProtocol", set_whois_protocol, NULL, RSRC_CONF,
			 "Whether this server is serving the whois protocol"),
	AP_INIT_TAKE1("WhoisDisclaimer", set_disclaimer_file, NULL, RSRC_CONF,
			 "File name with disclaimer which is standard part"
			 "of every whois response"),
	AP_INIT_TAKE1("WhoisObject", set_whois_object, NULL, RSRC_CONF,
			 "Name under which the whois object is known to "
			 "nameserver. Default is \"Whois\"."),
	{ NULL }
};

/**
 * Create server configuration for whoisd module.
 *
 * @param p   Pool used for allocations.
 * @param s   Server structure.
 */
static void *create_whoisd_config(apr_pool_t *p, server_rec *s)
{
	whoisd_server_conf *sc =
	    (whoisd_server_conf *) apr_pcalloc(p, sizeof(*sc));

	return sc;
}

/**
 * Function registering hooks of whoisd module.
 *
 * @param p   Pool used for allocations.
 */
static void register_hooks(apr_pool_t *p)
{
	static const char * const aszPre[]={ "mod_corba.c", NULL };

	ap_hook_post_config(whois_postconfig_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(process_whois_connection, aszPre, NULL,
			APR_HOOK_MIDDLE);

	/* register whois filters */
	ap_register_output_filter("WHOIS_OUTPUT_FILTER", whois_output_filter,
			NULL, AP_FTYPE_CONNECTION);
}

/**
 * Definition of whoisd module.
 */
module AP_MODULE_DECLARE_DATA whoisd_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_whoisd_config,       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    whoisd_cmds,                /* command apr_table_t */
    register_hooks              /* register hooks */
};

/* vi:set ts=8 sw=8: */
