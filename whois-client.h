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
 * This is the core of whois module. This function performs actual query
 * for domain.
 *
 * @par domain	Domain name
 * @ret Status (see defines above)
 */
int whois_corba_call(const char *domain);

#endif /* WHOIS_CLIENT_H */
