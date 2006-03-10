/*
 * Copyright statement
 */

#include "httpd.h"
#include "http_log.h"
#define CORE_PRIVATE
#include "http_config.h"
#include "http_protocol.h"	/* request_rec initializers */
#include "http_connection.h"	/* connection hooks */
#undef CORE_PRIVATE

#include "apr.h"
#include "apr_buckets.h"
#include "apr_file_io.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "scoreboard.h"
#include "util_filter.h"

#define WHOISD_VERSION	"0.1"
#define DEFAULT_DISCLAIMER	"Domain Information over Whois protocol\n"
#define INT_ERROR_MSG	"Internal server error occured when processing your request\n"

#define MAX_WHOIS_REQUEST_LENGTH	300 	/* should be enough */
#define MIN_WHOIS_REQUEST_LENGTH	3 	/* minimal domain name length */

module AP_MODULE_DECLARE_DATA whoisd_module;

/**
 * Configuration structure of whoisd module.
 */
typedef struct {
	int	whoisd_enabled;
	char *disclaimer_filename;
	char *disclaimer;
} whoisd_server_conf;

/**
 * Whois request processor.
 * Response to client is produced step-by-step by gluing of buckets.
 * @param r Initialized request waiting to be processed
 * @ret Result of processing
 */
static apr_status_t process_whois_request(request_rec *r)
{
	apr_status_t	status;
	apr_time_exp_t	now;
	apr_bucket_brigade *bb;
	server_rec	*s = r->server;
	whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);

	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	/*
	 * 	Do the actual CORBA function call
	 *
	whois_domain_restrictedinfo(result, r->uri, domain, registrar, techs, nameservers);
	 */

	/* TODO try what is flush arg */
	apr_brigade_printf(bb, NULL, NULL, "Whoisd Server Version: %s\n",
			WHOISD_VERSION);
	apr_brigade_puts(bb, NULL, NULL, sc->disclaimer);

	/* get time of response generation */
	status = apr_time_exp_gmt(&now, apr_time_now()); /* get current time */
	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					"Could not get current time! Using undefined value.");
	}
	apr_brigade_printf(bb, NULL, NULL,
		"Timestamp: %04d-%02d-%02d %02d:%02d:%02d (YYYY-MM-DD HH:MM:SS) GMT\n",
		1900 + now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour,
		now.tm_min, now.tm_sec);

	/*
	if (result == OK) {
		generate domain info
	}
	else {
	*/
		apr_brigade_puts(bb, NULL, NULL, INT_ERROR_MSG);
	/*
	}
	*/
	
	/* ok, finish it */
	APR_BRIGADE_INSERT_TAIL(bb,
			apr_bucket_eos_create(r->connection->bucket_alloc));
	status = ap_fflush(r->output_filters, bb);
	if (status != APR_SUCCESS) {
		  ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
						  "Error when sending response");
		  return APR_EGENERAL;
	}

	return APR_SUCCESS;
}


/**
 * Map whois request to http request.
 * @param c Actual connection
 * @ret Newly created request
 */
static request_rec *create_request(conn_rec *c)
{
    apr_pool_t *p;
    request_rec *r;

    apr_pool_create(&p, c->pool);
	apr_pool_tag(p, "Whois_request");

	/* theese are necessary */
    r                  = apr_pcalloc(p, sizeof(*r));
    r->pool            = p;
    r->connection      = c;
    r->server          = c->base_server;
    r->output_filters  = c->output_filters;
    r->input_filters   = c->input_filters;
    r->status          = HTTP_OK;


	/* theese are not essential, may be pruned away */
	r->request_time    = apr_time_now();
	r->no_cache        = 1;
	r->no_local_copy   = 1;

	/* required burden when using http request struct for whois request */
    r->allowed_methods = ap_make_method_list(p, 2);
    r->headers_in      = apr_table_make(r->pool, 1);
    r->subprocess_env  = NULL;
    r->headers_out     = apr_table_make(r->pool, 1);
    r->err_headers_out = apr_table_make(r->pool, 1);
    r->notes           = apr_table_make(r->pool, 5);
    r->request_config  = ap_create_request_config(r->pool);
    ap_run_create_request(r);

    return r;
}

/**
 * Will read whois user request (one line of text).
 * @param r Request structure
 * @param len Length of read string
 * @ret Read string
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
			ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					"Error when reading request");
			return NULL;
		}
		/* convert brigade into string */
		status = apr_brigade_pflatten(bb, &buf, len, r->pool);
		if (status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					"Could not flatten apr_brigade!");
			return NULL;
		}

		return buf;
}

/**
 * Connection handler.
 *
 * @param c Incoming connection
 */
static int process_whois_connection(conn_rec *c)
{
	int	eor;	/* end of request (domain name) */
	request_rec	*r;
	server_rec	*s = c->base_server;
	whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);
	apr_status_t	status;
	apr_size_t	len;

	ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
			"whois connection handler (whoisd_enabled=%d)", sc->whoisd_enabled);
	/* do nothing if whoisd is disabled */
	if (!sc->whoisd_enabled)
		return DECLINED;

	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);

	/* add connection output filters */
	ap_add_output_filter("WHOIS_OUTPUT_FILTER", NULL, NULL, c);

	/* create request */
	r = create_request(c);

	/*
	 * read request
	 * we use r->uri for storing domain name, other options are possible
	 */
	r->uri = read_request(r, &len);
	if (r->uri == NULL) return HTTP_INTERNAL_SERVER_ERROR;

	/* check if request isn't too long */
	if (len > MAX_WHOIS_REQUEST_LENGTH) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Request length too long (%d bytes)", len);
		return HTTP_BAD_REQUEST;
	}
	/* request might be also too short (2 = <CR><LF>) */
	if (len < MIN_WHOIS_REQUEST_LENGTH + 2) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Request length too short (%d bytes)", len);
		return HTTP_BAD_REQUEST;
	}
	/*
	 * each request has to be terminated by <CR><LF>, apr_get_brigade returns
	 * whatever text is available, so we have to explicitly check for it
	 */
	if (r->uri[len - 1] != '\n' || r->uri[len - 2] != '\r') {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Request is not terminated by <CR><LF>");
		return HTTP_BAD_REQUEST;
	}
	/* strip <CR><LF> characters */
	r->uri[len - 2] = 0;

	/* process request */
	status = process_whois_request(r);
	if (status != APR_SUCCESS) return HTTP_INTERNAL_SERVER_ERROR;

	return OK;
}

/**
 * Whois output filter. (TODO be more specific)
 */
static apr_status_t whois_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    return ap_pass_brigade(f->next, bb);
}

static int postconfig_hook(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
																server_rec *s)
{
	whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);
	/*
	 * We load content of disclaimer file in memory, so we don't have to
	 * perform filesystem read upon every response.
	 */
	if (sc->whoisd_enabled) {
		if (sc->disclaimer_filename == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			 "mod_whoisd: whoisd is enabled and disclaimer filename is not set");
			sc->servername = apr_pstrdup(p, DEFAULT_SERVERNAME);
			return 1;
		}
		else {
			/* XXX continue
			 * 1) open file disclaimer
			 * 2) read contents
			 * 3) close file disclaimer
			 */
		}
	}

	return OK;
}

static const char *set_whois_protocol(cmd_parms *cmd, void *dummy, int flag)
{
    server_rec *s = cmd->server;
    whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);

	const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }

    sc->whoisd_enabled = flag;
    return NULL;
}

static const char *set_disclaimer_file(cmd_parms *cmd, void *dummy, const char *a1)
{
    server_rec *s = cmd->server;
    whoisd_server_conf *sc = (whoisd_server_conf *)
		ap_get_module_config(s->module_config, &whoisd_module);

	const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }

    sc->disclaimer_file = a1;
    return NULL;
}

static const command_rec whoisd_cmds[] = {
    AP_INIT_FLAG("WhoisProtocol", set_whois_protocol, NULL, RSRC_CONF,
			 "Whether this server is serving the whois protocol"),
	AP_INIT_TAKE1("DisclaimerFile", set_disclaimer_file, NULL, RSRC_CONF,
			 "File with disclaimer which is standard part of every response");
    { NULL }
};

static void *create_whoisd_config(apr_pool_t *p, server_rec *s)
{
	whoisd_server_conf *sc =
	    (whoisd_server_conf *) apr_palloc(p, sizeof(whoisd_server_conf));

    sc->whoisd_enabled = 0; /* by default is whoisd turned off */
	return sc;
}

static void register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(postconfig_hook, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_process_connection(process_whois_connection, NULL, NULL, APR_HOOK_MIDDLE);

	/* register whois filters */
	ap_register_output_filter("WHOIS_OUTPUT_FILTER", whois_output_filter, NULL,
				                              AP_FTYPE_CONNECTION);
}

module AP_MODULE_DECLARE_DATA whoisd_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_whoisd_config,       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    whoisd_cmds,                /* command apr_table_t */
    register_hooks              /* register hooks */
};

/* TODO: pozdrzet odpoved o kratky casovy interval */
/* vi:set ts=4 sw=4: */
