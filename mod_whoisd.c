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

#define MIN_WHOIS_REQUEST_LENGTH 1   /**< Minimal object (domain) name length. */
/** Maximal allowed length of object (domain) name. */
#define MAX_WHOIS_REQUEST_LENGTH 1000
/** Length of buffer used to hold time of response generation. */
#define TIME_BUFFER_LENGTH 50

module AP_MODULE_DECLARE_DATA whoisd_module; /**< Whois module declaration. */

/**
 * Configuration structure of whoisd module.
 */
typedef struct {
	int	whoisd_enabled; /**< Enabled/disabled flag. */
	const char *disclaimer_filename; /**< File with disclaimer. */
	char *disclaimer; /**< Disclaimer as a string. */
	const char *webwhois_url; /**< URL of web based whois. */
	char *object; /**< Name of whois object. */
	apr_interval_time_t	delay; /**< Used for meassuring of CORBA call latency. */
}whoisd_server_conf;

#if AP_SERVER_MINORVERSION_NUMBER == 0
/**
 * This is wrapper function for compatibility reason. Apache 2.0 does
 * not have ap_log_cerror, instead we will use ap_log_error.
 */
#define ap_log_cerror(mark, level, status, c, ...) \
	ap_log_error(mark, level, status, (c)->base_server, __VA_ARGS__)
#endif

/**
 * Whois request processor.
 *
 * This function is called from connection handler. It performs
 * a CORBA call through CORBA backend and then processes data and
 * sends typical whois answer. Response to client is produced step-by-step
 * by gluing of buckets.
 *
 * @param r Initialized request waiting to be processed
 * @return Result of processing
 */
static apr_status_t process_whois_request(request_rec *r)
{
	int	rc;
	int i;
	char	pending_comment; /* pending nl from previous bucket (boolean) */
	char	timebuf[TIME_BUFFER_LENGTH]; /* buffer for time of resp. gen. */
	whois_data_t	*wd; /* whois data returned from CORBA backend */
	apr_time_t	time1, time2; /* meassuring of CORBA server latency */
	apr_status_t	status;
	apr_bucket_brigade *bb; /* brigade for response */
	apr_bucket	*b; /* used for escaping of disclaimer */
	service_Whois	service;
	apr_hash_t	*references;
	module	*corba_module;
	server_rec	*s = r->server;
	whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);

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
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
				"mod_corba module was not loaded - unable to handle a whois "
				"request");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	references = (apr_hash_t *)
		ap_get_module_config(r->connection->conn_config, corba_module);
	if (references == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
				"mod_corba is not enabled for this server though it "
				"should be! Cannot handle whois request.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	service = (service_Whois *) apr_hash_get(references, sc->object,
			strlen(sc->object));
	if (service == NULL) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
				"Could not obtain object reference for alias '%s'. Check "
				"mod_corba's configuration.", sc->object);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* We will meassure the time the corba function call takes. */
	time1 = apr_time_now();
	/* call corba function, return code will be analyzed later */
	rc = whois_corba_call(service, r->uri, &wd, timebuf,
			TIME_BUFFER_LENGTH);
	time2 = apr_time_now();

	ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, r->connection,
			"Request for \"%s\" processed in %u ms",
			r->uri, (unsigned int) (time2 - time1) / 1000);

	/* this brigade is used for response */
	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

	/* TODO try what is flush arg in bucket printing routines */

	/*
	 * Print disclaimer into bucket, note that this disclaimer is not
	 * properly escaped yet. Escaping is done bellow in 'for' loop.
	 */
	apr_brigade_printf(bb, NULL, NULL, "Whoisd Server Version: %s\n\n",
			PACKAGE_VERSION);
	apr_brigade_puts(bb, NULL, NULL, sc->disclaimer);
	if (rc != CORBA_SERVICE_FAILED && rc != CORBA_INTERNAL_ERROR)
		apr_brigade_printf(bb, NULL, NULL, "Timestamp: %s\n", timebuf);

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
		 b  = APR_BUCKET_NEXT(b)) {
		const char *str, *pos;
		apr_size_t	len;
		apr_bucket *bnew;

		/*
		 * if we have found nl at the end of previous bucket, insert comment
		 * sign before current bucket
		 */
		if (pending_comment) {
			bnew = apr_bucket_heap_create("% ", 2, NULL,
					r->connection->bucket_alloc);
			APR_BUCKET_INSERT_BEFORE(b, bnew);
			pending_comment = 0;
		}

        status = apr_bucket_read(b, &str, &len, APR_NONBLOCK_READ);
        if (status != APR_SUCCESS) {
            return status;
        }

		/* while there is a match */
		if ((pos = memchr(str, APR_ASCII_LF, len)) != NULL) {
			/*
			 * if ln is last char in bucket, don't split the bucket and
			 * defer comment insertion.
			 */
			if (pos - str == len - 1) {
				pending_comment = 1;
			}
			else {
				apr_bucket_split(b, pos - str + 1);
				bnew = apr_bucket_heap_create("% ", 2, NULL,
						r->connection->bucket_alloc);
				APR_BUCKET_INSERT_AFTER(b, bnew);
				b = bnew; /* move one bucket ahead */
			}
		}
	}
	/* this new line will not be escaped */
	apr_brigade_puts(bb, NULL, NULL,   "\n");

	/* analyze return code from CORBA function call */
	switch (rc) {
		case CORBA_DOMAIN_INVALID:
			apr_brigade_puts(bb, NULL, NULL,   "Invalid domain name.\n");
			break;
		case CORBA_DOMAIN_LONG:
			apr_brigade_puts(bb, NULL, NULL,   "Domain name is too long.\n");
			break;
		case CORBA_DOMAIN_BAD_ZONE:
			apr_brigade_printf(bb, NULL, NULL, "Domain:      %s\n", r->uri);
			apr_brigade_puts(bb, NULL, NULL,   "Status:      UNKNOWN\n");
			apr_brigade_puts(bb, NULL, NULL,   "Domain is not managed by "
					"this registry.\n");
			break;
		case CORBA_DOMAIN_FREE:
			apr_brigade_printf(bb, NULL, NULL, "Domain:      %s\n", r->uri);
			apr_brigade_puts(bb, NULL, NULL,   "Status:      FREE\n");
			break;
		case CORBA_OK:
			/* generate domain info */
			apr_brigade_printf(bb, NULL, NULL,"Domain:      %s\n", wd->fqdn);
			/* domain status */
			if (wd->status == DOMAIN_ACTIVE)
				apr_brigade_puts(bb,NULL,NULL,"Status:      REGISTERED\n");
			else
				apr_brigade_puts(bb,NULL,NULL,"Status:      EXPIRED\n");
			/* creation date */
			apr_brigade_printf(bb, NULL, NULL,"Registered:  %s\n", wd->created);
			/* expiration date */
			apr_brigade_printf(bb, NULL, NULL,"Expiration:  %s\n\n",wd->expired);
			/* Registrant info */
			apr_brigade_puts(bb, NULL, NULL,  "Registrant:");
			if (wd->enum_domain)
				apr_brigade_printf(bb, NULL, NULL, "  Not available\n");
			else
				apr_brigade_printf(bb, NULL, NULL,
						"\n   Please visit webbased whois at %s for more\n"
						"information.\n\n", sc->webwhois_url);
			/* Registrar info */
			apr_brigade_puts(bb, NULL, NULL, "Registrar:\n");
			apr_brigade_printf(bb, NULL, NULL, "   Name:    %s\n",
					wd->registrarName);
			apr_brigade_printf(bb, NULL, NULL, "   Website: %s\n\n",
					wd->registrarUrl);
			/* tech contacts */
			apr_brigade_puts(bb, NULL, NULL, "Technical Contact:\n");
			for (i = 0; i < wd->tech_length; i++)
				apr_brigade_printf(bb, NULL, NULL, "   %s\n", wd->techs[i]);
			/* Name servers */
			apr_brigade_puts(bb, NULL, NULL, "\n");
			apr_brigade_puts(bb, NULL, NULL, "Nameservers:\n");
			for (i = 0; i < wd->ns_length; i++)
				apr_brigade_printf(bb, NULL, NULL, "   %s\n",
						wd->nameservers[i]);

			whois_release_data(wd);
			break;
		case CORBA_UNKNOWN_ERROR:
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
					"Corba returned unknown error type - check that mod_whoisd "
					"is not out of sync with IDL file.");
			apr_brigade_puts(bb, NULL, NULL, INT_ERROR_MSG);
			break;
		case CORBA_INTERNAL_ERROR:
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
					"Corba internal error - Memory allocation failed");
			apr_brigade_puts(bb, NULL, NULL, INT_ERROR_MSG);
			break;
		case CORBA_SERVICE_FAILED:
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
					"Corba service failed ... perhaps CORBA server isn't "
					"running?");
			apr_brigade_puts(bb, NULL, NULL, INT_ERROR_MSG);
			break;
		default:
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
					"Corba call failed with unknown error code");
			apr_brigade_puts(bb, NULL, NULL, INT_ERROR_MSG);
			break;
	}

	/* ok, finish it - flush what we have produced so far */
	APR_BRIGADE_INSERT_TAIL(bb,
			apr_bucket_eos_create(r->connection->bucket_alloc));
	status = ap_fflush(r->output_filters, bb);
	if (status != APR_SUCCESS) {
		  ap_log_cerror(APLOG_MARK, APLOG_ERR, status, r->connection,
						  "Error when sending response");
		  return APR_EGENERAL;
	}

	return APR_SUCCESS;
}

/**
 * Map whois request to http request.
 * The created request_rec cannot be used in standard routines in
 * place of http request_rec. Some fields are not properly initialized
 * becauseof a differences between http and whois request.
 *
 * @param c Actual connection
 * @return Newly created request
 */
static request_rec *create_request(conn_rec *c)
{
    apr_pool_t *p;
    request_rec *r;

    apr_pool_create(&p, c->pool);
	apr_pool_tag(p, "Whois_request");

	/* these are necessary */
    r                  = apr_pcalloc(p, sizeof(*r));
    r->pool            = p;
    r->connection      = c;
    r->server          = c->base_server;
    r->output_filters  = c->output_filters;
    r->input_filters   = c->input_filters;
    r->status          = HTTP_OK;


	/* these are not essential, may be pruned away */
	r->request_time    = apr_time_now();
	r->no_cache        = 1;
	r->no_local_copy   = 1;
	r->assbackwards    = 1; /* denotes http/0.9 request (without headers) */

    /*
	 * The problem with ap_run_create_request is that it runs whatever
	 * is registered for request creation. Those hooks assume that they
	 * operate on http request, which is true only partialy. Although
	 * we map whois request to http's request_rec, not all operations
	 * on whois request are meaningful. For example registering of
	 * default http output filters, is causing some troubles. What more,
	 * any loaded module can register hook for request creation and take
	 * action that would be appropriate for http request but not for whois
	 * request. You can uncomment following part and make whois
	 * request as much as possible "http friendly", but you have been warned.

	// required burden when using http request struct for whois request
    r->allowed_methods = ap_make_method_list(p, 2);
    r->headers_in      = apr_table_make(r->pool, 1);
    r->subprocess_env  = NULL; // Why NULL? Don't know - copied from mod_pop3
    r->headers_out     = apr_table_make(r->pool, 1);
    r->err_headers_out = apr_table_make(r->pool, 1);
    r->notes           = apr_table_make(r->pool, 5);
    r->request_config  = ap_create_request_config(r->pool);

	// denotes that request doesn't contain any headers (simple http/0.9)
	r->assbackwards    = 1;
	ap_run_create_request(r);
	*/

    return r;
}

/**
 * This will read whois request (one line of text).
 *
 * @param r Request structure.
 * @param len Length of request.
 * @return The string which was read, NULL in case of error.
 */
static char *read_request(request_rec *r, apr_size_t *len)
{
		char *buf; /* buffer for user request */
		apr_bucket_brigade *bb;
		apr_status_t	status;

		bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

		/*
		 * blocking read of one line of text
		 * Last argument seems to be ignored by ap_get_brigade when
		 * reading one line (it should be max number of bytes to read)
		 */
		status = ap_get_brigade(r->input_filters, bb, AP_MODE_GETLINE,
									APR_BLOCK_READ, 0);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, r->connection,
					"Error when reading request");
			return NULL;
		}
		/* convert brigade into string */
		status = apr_brigade_pflatten(bb, &buf, len, r->pool);
		if (status != APR_SUCCESS) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, status, r->connection,
					"Could not flatten apr_brigade!");
			return NULL;
		}

		return buf;
}

/**
 * Connection handler of mod_whoisd module.
 *
 * If mod_whoisd is for server enabled, the request is read (assuming
 * it is whois request) and processed in request handler, which is called
 * from inside of this function.
 *
 * @param c Incomming connection.
 * @return Status.
 */
static int process_whois_connection(conn_rec *c)
{
	apr_status_t	status;
	apr_size_t	len;/* length of whois request */
	request_rec	*r; /* http request - used for whois request */
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

	/* create and initialize http request */
	r = create_request(c);

	/*
	 * read request
	 * we use r->uri for storing domain name, other options are possible
	 */
	r->uri = read_request(r, &len);
	if (r->uri == NULL) return HTTP_INTERNAL_SERVER_ERROR;

	/* check if request isn't too long */
	if (len > MAX_WHOIS_REQUEST_LENGTH) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Request length too long (%u bytes)", (unsigned) len);
		return HTTP_BAD_REQUEST;
	}
	/* request might be also too short (2 = <CR><LF>) */
	if (len < MIN_WHOIS_REQUEST_LENGTH + 2) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Request length too short (%u bytes)", (unsigned) len);
		return HTTP_BAD_REQUEST;
	}
	/*
	 * each request has to be terminated by <CR><LF>, apr_get_brigade returns
	 * whatever text is available, so we have to explicitly check for it
	 */
	if (r->uri[len - 1] != APR_ASCII_LF || r->uri[len - 2] != APR_ASCII_CR) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
				"Request is not terminated by <CR><LF>");
		return HTTP_BAD_REQUEST;
	}
	/* strip <CR><LF> characters */
	r->uri[len - 2] = 0;

	/* defer request - prevents data mining */
	apr_sleep(sc->delay);

	/* process request */
	status = process_whois_request(r);
	if (status != APR_SUCCESS) return HTTP_INTERNAL_SERVER_ERROR;

	return OK;
}

/**
 * Whois output filter inserts in front of every <LF>, which is not
 * preceeded by <CR>, <CR>.
 *
 * @param f Chain of filters.
 * @bb bb Bucket brigade to be filtered.
 * @return Status.
 */
static apr_status_t whois_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_bucket	*b, *bnew;
	apr_size_t	len;
	apr_status_t	status;
	char *pos;
	const char *str;

	for (b = APR_BRIGADE_FIRST(bb);
		 b != APR_BRIGADE_SENTINEL(bb);
		 b = APR_BUCKET_NEXT(b)) {

        status = apr_bucket_read(b, &str, &len, APR_NONBLOCK_READ);

        if (status != APR_SUCCESS) {
            return status;
        }
		/* not all buckets contain string (for instance EOS, FLUSH don't) */
		if (str == NULL) continue;

		/*
		 * while there is a match cut the bucket in 3 parts ... '\n' ... and
		 * insert <CR> where apropriate
		 */
		if ((pos = memchr(str, APR_ASCII_LF, len)) != NULL) {
			if (pos == str) {
				bnew = apr_bucket_heap_create("\r", 1, NULL, f->c->bucket_alloc);
				APR_BUCKET_INSERT_BEFORE(b, bnew);
				if (len > 1) apr_bucket_split(b, 1);
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
 * @param p Pool to allocate from.
 * @param plog Pool used for logging.
 * @param ptemp Temporary pool.
 * @param s Server struct.
 * @return Status.
 */
static int whois_postconfig_hook(apr_pool_t *p, apr_pool_t *plog,
		apr_pool_t *ptemp, server_rec *s)
{
	whoisd_server_conf *sc;
	int	err_seen = 0;

	/*
	 * Iterate through available servers and if whoisd is enabled
	 * do further checking
	 */
	while (s != NULL) {
		sc = (whoisd_server_conf *) ap_get_module_config(s->module_config,
				&whoisd_module);

		if (sc->whoisd_enabled) {
			if (sc->disclaimer_filename == NULL) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
					 "mod_whoisd: whoisd is enabled and disclaimer filename "
					 "is not set");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (sc->webwhois_url == NULL) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
					 "mod_whoisd: whoisd is enabled and webbased whois url "
					 "is not set");
				return HTTP_INTERNAL_SERVER_ERROR;
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
	return (err_seen) ? HTTP_INTERNAL_SERVER_ERROR : OK;
}

/**
 * Routine disables or enables the operation of mod_whois.
 *
 * @param cmd Command.
 * @param dummy Not used arg.
 * @param flag The value.
 * @return NULL if OK, otherwise a string.
 */
static const char *set_whois_protocol(cmd_parms *cmd, void *dummy, int flag)
{
	const char *err;
    server_rec *s = cmd->server;
    whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);
	
	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) return err;

    sc->whoisd_enabled = flag;
    return NULL;
}

/**
 * Routine accepts URL of web whois, which is printed instead of domain owner
 * in whois response.
 *
 * @param cmd Command.
 * @param dummy Not used arg.
 * @param a1 The value.
 * @return NULL if OK, otherwise a string.
 */
static const char *set_webwhois_url(cmd_parms *cmd, void *dummy, const char *a1)
{
	const char *err;
    server_rec *s = cmd->server;
    whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) return err;

	/*
	 * catch double definition of url
	 * that's not serious fault so we will just print log message
	 */
	if (sc->webwhois_url != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_whoisd: more than one definition of WhoisWebURL. All but\
			the first one will be ignored");
		return NULL;
	}

	sc->webwhois_url = apr_pstrdup(cmd->pool, a1);
	return NULL;
}

/**
 * Routine accepts name of file with disclaimer, it also reads the file
 * and stores disclaimer in server configuration struct.
 *
 * @param cmd Command.
 * @param dummy Not used arg.
 * @param a1 The value.
 * @return NULL if OK, otherwise a string.
 */
static const char *set_disclaimer_file(cmd_parms *cmd, void *dummy,
		const char *a1)
{
	const char *err;
	char	buf[101];
	char	*res;
	apr_file_t	*f;
	apr_size_t	nbytes;
	apr_status_t	status;
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
			"mod_whoisd: more than one definition of DisclaimerFile. All but\
			the first one will be ignored");
		return NULL;
	}

	sc->disclaimer_filename = a1;

	/* open file */
	status = apr_file_open(&f, sc->disclaimer_filename, APR_FOPEN_READ,
			APR_OS_DEFAULT, cmd->temp_pool);
	if (status != APR_SUCCESS) {
		return apr_psprintf(cmd->temp_pool,
					"mod_whoisd: could not open file %s (disclaimer)",
					sc->disclaimer_filename);
	}

	/* read the file */
	res = apr_pstrdup(cmd->temp_pool, " ");
	nbytes = 100;
	while ((status = apr_file_read(f, (void *) buf, &nbytes)) == APR_SUCCESS) {
		buf[nbytes] = 0;
		res = apr_pstrcat(cmd->temp_pool, res, buf, NULL);
		nbytes = 100;
	}
	if (status != APR_EOF) {
		return apr_psprintf(cmd->temp_pool,
				"mod_whoisd: error when reading file %s (disclaimer)",
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
					"mod_whoisd: error when closing file %s",
					sc->disclaimer_filename);
	}

	sc->disclaimer = apr_pstrdup(cmd->pool, res);

    return NULL;
}

/**
 * Routine sets name under which is registered whois object by nameservice.
 *
 * @param cmd Command.
 * @param dummy Not used arg.
 * @param name The value.
 * @return NULL if OK, otherwise a string.
 */
static const char *set_whois_object(cmd_parms *cmd, void *dummy,const char *name)
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
			"mod_whoisd: more than one definition of whois object name. All \
			but the first one will be ignored");
		return NULL;
	}

	sc->object = apr_pstrdup(cmd->pool, name);

    return NULL;
}

/**
 * Routine sets delay before the response is sent back to client.
 *
 * Whois delay is defence against data miners.
 *
 * @param cmd Command.
 * @param dummy Not used arg.
 * @param a1 The value.
 * @return NULL if OK, otherwise a string.
 */
static const char *set_whois_delay(cmd_parms *cmd, void *dummy, const char *a1)
{
	char	*p;
	const char *err;
    server_rec *s = cmd->server;
    whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);
	
	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) return err;

	/* do some basic checking */
	for (p = (char *) a1; *p; p++)
		if (!apr_isdigit(*p)) return "WhoisDelay value is not a number";
	if (p - a1 > 4)
		return "WhoisDelay value is out of range, must be 0 .. 9999";

	/* sleep() accepts microseconds so convert mili to micro */
    sc->delay = atoi(a1) * 1000;

    return NULL;
}

/** Structure defining configuration options for whoisd module. */
static const command_rec whoisd_cmds[] = {
    AP_INIT_FLAG("WhoisProtocol", set_whois_protocol, NULL, RSRC_CONF,
			 "Whether this server is serving the whois protocol"),
	AP_INIT_TAKE1("WhoisDisclaimer", set_disclaimer_file, NULL, RSRC_CONF,
			 "File name with disclaimer which is standard part"
			 "of every whois response"),
	AP_INIT_TAKE1("WhoisWebURL", set_webwhois_url, NULL, RSRC_CONF,
			 "This URL is printed instead of registrant's info"
			 " with explanational note"),
	AP_INIT_TAKE1("WhoisDelay", set_whois_delay, NULL, RSRC_CONF,
			 "Number of miliseconds the responce to client will be deferred. "
			 "Number must be in range 0 to 9999"),
	AP_INIT_TAKE1("WhoisObject", set_whois_object, NULL, RSRC_CONF,
			 "Name under which is the whois object known to nameserver. "
			 "Default is \"Whois\"."),
    { NULL }
};

/**
 * Create server configuration for whoisd module.
 *
 * @param p Pool used for allocations.
 * @param s Server structure.
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
 * @param p Pool used for allocations.
 */
static void register_hooks(apr_pool_t *p)
{
	static const char * const aszPre[]={ "mod_corba.c", NULL };

	ap_hook_post_config(whois_postconfig_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(process_whois_connection, aszPre, NULL,
			APR_HOOK_MIDDLE);

	/* register whois filters */
	ap_register_output_filter("WHOIS_OUTPUT_FILTER", whois_output_filter, NULL,
				                              AP_FTYPE_CONNECTION);
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

/* vi:set ts=4 sw=4: */
