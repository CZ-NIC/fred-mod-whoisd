#ifndef WHOIS_CLIENT_H
#define WHOIS_CLIENT_H

/*
 * define return codes. Theese are used in apache module to analyze
 * what happened during corba call. Appropriate apache log message is
 * then generated.
 */
#define CORBA_OK	0
#define CORBA_INIT_FAILED	1
#define CORBA_IMPORT_FAILED	2
#define CORBA_SERVICE_FAILED	3

/**
 * Structure holding domain data. Name is not included since it is known
 * by caller.
 */
typedef struct {
	long long created;
	long long expired;
	char *registrarName;
	char *registrarUrl;
	char *nameservers;
	int  ns_length;
} whois_data_t;

/**
 * This is the core of whois module. This function performs actual query
 * for domain.
 *
 * @par domain	Domain name
 * @ret Status (see defines above)
 */
int whois_corba_call(const char *domain, whois_data_t *wd);

/**
 * Release content of whois_data_t structure. We don't want to mix apache
 * pools with malloc and free routines within one file, so we have to
 * explicitly call this function in order to release whois data returned
 * from previous call.
 * @par wd Whois data to be freed
 */
void whois_release_data(whois_data_t *wd);

#endif /* WHOIS_CLIENT_H */
