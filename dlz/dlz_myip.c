/*
 * dlz_myip.c (C)2013 by Jan-Piet Mens <jpmens@gmail.com>
 * A dlz_dlopen() driver for BIND's named which returns the address
 * of the caller. Configure this in named.conf as
 *
 *       dlz "example.com" {
 *	      database "dlopen path/to/dlz_myip.so example.com";
 *	 };
 *
 * An A query to the zone apex will return an A RR with the IPv4 of the
 * caller. An AAAA query to the zone apex with return the AAAA of the 
 * caller, if over an IPv6 interface.
 *
 * Build with:
 *
 * 	$(CC) -fPIC -shared -o dlz_myip.so dlz_myip.c
 *
 * Most of this code is taken from
 *	$Id: dlz_example.c,v 1.3 2011-10-20 22:01:48 each Exp $ 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "dlz_minimal.h"

struct dlz_example_data {
	char *zone_name;

	isc_boolean_t transaction_started;

	/* Helper functions from the dlz_dlopen driver */
	log_t *log;
	dns_sdlz_putrr_t *putrr;
	dns_sdlz_putnamedrr_t *putnamedrr;
	dns_dlz_writeablezone_t *writeable_zone;

};

static isc_result_t
fmt_address(isc_sockaddr_t *addr, char *buffer, size_t size) {
	char addr_buf[100];
	const char *ret;

	switch (addr->type.sa.sa_family) {
	case AF_INET:
		ret = inet_ntop(AF_INET, &addr->type.sin.sin_addr, addr_buf,
				sizeof(addr_buf));
		break;
	case AF_INET6:
		ret = inet_ntop(AF_INET6, &addr->type.sin6.sin6_addr, addr_buf,
				sizeof(addr_buf));
		break;
	default:
		return (ISC_R_FAILURE);
	}

	if (ret == NULL)
		return (ISC_R_FAILURE);

	snprintf(buffer, size, "%s", addr_buf);
	return (ISC_R_SUCCESS);
}

/*
 * Return the version of the API
 */
int
dlz_version(unsigned int *flags) {
	UNUSED(flags);
	return (DLZ_DLOPEN_VERSION);
}

/*
 * Remember a helper function from the bind9 dlz_dlopen driver
 */
static void
b9_add_helper(struct dlz_example_data *state,
	      const char *helper_name, void *ptr)
{
	if (strcmp(helper_name, "log") == 0)
		state->log = (log_t *)ptr;
	if (strcmp(helper_name, "putrr") == 0)
		state->putrr = (dns_sdlz_putrr_t *)ptr;
	// if (strcmp(helper_name, "putnamedrr") == 0)
	// 	state->putnamedrr = (dns_sdlz_putnamedrr_t *)ptr;
	// if (strcmp(helper_name, "writeable_zone") == 0)
	// 	state->writeable_zone = (dns_dlz_writeablezone_t *)ptr;
}

/*
 * Called to initialize the driver
 */
isc_result_t
dlz_create(const char *dlzname, unsigned int argc, char *argv[],
	   void **dbdata, ...)
{
	struct dlz_example_data *state;
	const char *helper_name;
	va_list ap;

	UNUSED(dlzname);

	state = calloc(1, sizeof(struct dlz_example_data));
	if (state == NULL)
		return (ISC_R_NOMEMORY);

	/* Fill in the helper functions */
	va_start(ap, dbdata);
	while ((helper_name = va_arg(ap, const char *)) != NULL) {
		b9_add_helper(state, helper_name, va_arg(ap, void*));
	}
	va_end(ap);

	if (argc < 2) {
		state->log(ISC_LOG_ERROR,
			   "dlz_myip: please specify a zone name");
		return (ISC_R_FAILURE);
	}

	state->zone_name = strdup(argv[1]);

	state->log(ISC_LOG_INFO,
		   "dlz_myip: started for zone %s", state->zone_name);

	*dbdata = state;
	return (ISC_R_SUCCESS);
}

/*
 * Shut down the backend
 */
void
dlz_destroy(void *dbdata) {
	struct dlz_example_data *state = (struct dlz_example_data *)dbdata;


	state->log(ISC_LOG_INFO,
		   "dlz_myip: shutting down zone %s", state->zone_name);

	free(state->zone_name);
	free(state);
}


/*
 * See if we handle a given zone
 */
isc_result_t
dlz_findzonedb(void *dbdata, const char *name) {
	struct dlz_example_data *state = (struct dlz_example_data *)dbdata;

	if (strcasecmp(state->zone_name, name) == 0)
		return (ISC_R_SUCCESS);

	return (ISC_R_NOTFOUND);
}

/*
 * Look up one record in the sample database.
 *
 * If the queryname is "source-addr", we add a TXT record containing
 * the address of the client; this demonstrates the use of 'methods'
 * and 'clientinfo'.
 */
isc_result_t
dlz_lookup(const char *zone, const char *name, void *dbdata,
	   dns_sdlzlookup_t *lookup, dns_clientinfomethods_t *methods,
	   dns_clientinfo_t *clientinfo)
{
	isc_result_t result = ISC_R_SUCCESS;
	struct dlz_example_data *state = (struct dlz_example_data *)dbdata;
	isc_boolean_t found = ISC_FALSE;
	isc_sockaddr_t *src;
	char full_name[512], client_addr[128], rdata[512];

	UNUSED(zone);

	if (strcmp(name, "@") == 0)
		strcpy(full_name, state->zone_name);
	else
		sprintf(full_name, "%s.%s", name, state->zone_name);

	fprintf(stderr, "+++++++ dlz: name=[%s], full_name=[%s]\n", name, full_name);

	/* Format client's address */
	strcpy(client_addr, "0.1.1.0");
	if (methods != NULL &&
	    methods->version - methods->age >=
		    DNS_CLIENTINFOMETHODS_VERSION)
	{
		methods->sourceip(clientinfo, &src);
		fmt_address(src, client_addr, sizeof(client_addr));
	}

	if (strcmp(name, "@") == 0) {
		sprintf(rdata, "root. %s 1 900 600 86400 3600", zone);
		result = state->putrr(lookup, "SOA", 60, rdata);
		
		// FIXME
		if (strchr(client_addr, ':')) {
			result = state->putrr(lookup, "AAAA", 60, client_addr);
		} else {
			result = state->putrr(lookup, "A", 60, client_addr);
		}
		found = 1;
	}

	if (!found)
		result =ISC_R_NOTFOUND;

	return (result);
}


/*
 * See if a zone transfer is allowed
 */
isc_result_t
dlz_allowzonexfr(void *dbdata, const char *name, const char *client) {
	UNUSED(client);

	return (ISC_R_NOTFOUND);
	return (ISC_R_FAILURE);
}

/*
 * Perform a zone transfer
 */
isc_result_t
dlz_allnodes(const char *zone, void *dbdata, dns_sdlzallnodes_t *allnodes) {

	UNUSED(zone);

	return (ISC_R_FAILURE);
}


/*
 * Configure a writeable zone
 */
isc_result_t
dlz_configure(dns_view_t *view, void *dbdata) {

	return (ISC_FALSE);
}

/*
 * Authorize a zone update
 */
isc_boolean_t
dlz_ssumatch(const char *signer, const char *name, const char *tcpaddr,
	     const char *type, const char *key, uint32_t keydatalen,
	     unsigned char *keydata, void *dbdata)
{
	UNUSED(tcpaddr);
	UNUSED(type);
	UNUSED(key);
	UNUSED(keydatalen);
	UNUSED(keydata);

	return (ISC_FALSE);
}

