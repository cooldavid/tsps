/*
 *  TSP Server
 *
 *  A TSP Server implementation that follows RFC5572 as much as possible.
 *  It is designed to be compatible with FreeNET6 service.
 *
 *  LDAP support
 *  Copyright (C) 2011  Stephen Rothwell <sfr@canb.auug.or.au>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>

#include "tsps.h"

static LDAP *ldp;

int tsps_ldap_initialize(void)
{
	int res;
	int val;
	struct berval passwd;

	res = ldap_initialize(&ldp, server.ldap_uri);
	if (res != LDAP_SUCCESS) {
		fprintf(stderr, "LDAP initialization error: %s\n",
			ldap_err2string(res));
		return -1;
	}
	val = LDAP_VERSION3;
	res = ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &val);
	if (res != LDAP_SUCCESS) {
		fprintf(stderr, "LDAP set_option error: %s\n",
			ldap_err2string(res));
		return -1;
	}
	/*
	 * do an anoymous bind
	 */
	memset(&passwd, 0, sizeof(passwd));
	res = ldap_sasl_bind_s(ldp, NULL, LDAP_SASL_SIMPLE, &passwd,
		NULL, NULL, NULL);
	if (res != LDAP_SUCCESS) {
		fprintf(stderr, "LDAP anonymous bind error: %s\n",
			ldap_err2string(res));
		return -1;
	}
	return 0;
}

int tsps_ldap_login(const char *user, const char *pass)
{
	char dn[1024];
	LDAP *lp;
	int res;
	int val;
	struct berval passwd;

	res = ldap_initialize(&lp, server.ldap_uri);
	if (res != LDAP_SUCCESS) {
		fprintf(stderr, "LDAP initialization error: %s\n",
			ldap_err2string(res));
		return -1;
	}
	val = LDAP_VERSION3;
	res = ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &val);
	if (res != LDAP_SUCCESS) {
		fprintf(stderr, "LDAP set_option error: %s\n",
			ldap_err2string(res));
		return -1;
	}
	/*
	 * Attempt to bind to the ldap server as the user
	 */
	snprintf(dn, sizeof(dn), "uid=%s,%s", user, server.ldap_user_base);
	memset(&passwd, 0, sizeof(passwd));
	passwd.bv_val = ber_strdup(pass);
	passwd.bv_len = strlen(pass);
	res = ldap_sasl_bind_s(lp, dn, LDAP_SASL_SIMPLE, &passwd,
		NULL, NULL, NULL);
	ldap_unbind_ext_s(lp, NULL, NULL);
	if (res != LDAP_SUCCESS) {
		fprintf(stderr, "LDAP bind error: %s\n",
			ldap_err2string(res));
		return -1;
	}
	return 0;
}

int tsps_ldap_get_userid(const char *user)
{
	char user_filt[128];
	int res;
	char *attrs[] = { "uidNumber", NULL };
	LDAPMessage *vals = NULL;
	LDAPMessage *val;
	int uidnum = -1;

	snprintf(user_filt, sizeof(user_filt), "(uid=%s)", user);
	
	res = ldap_search_ext_s(ldp, server.ldap_user_base,
		LDAP_SCOPE_ONELEVEL, user_filt, attrs, 0, NULL, NULL,
		NULL, 0, &vals);
	if (res != LDAP_SUCCESS) {
		fprintf(stderr, "LDAP search error: %s\n",
			ldap_err2string(res));
		return -1;
	}

	for (val = ldap_first_message(ldp, vals); val;
			val = ldap_next_message(ldp, val)) {
		struct berval **uid_val =
			ldap_get_values_len(ldp, val, "uidNumber");

		if (uid_val) {
			uidnum = (int)strtol(uid_val[0]->bv_val, NULL, 0);
			ldap_value_free_len(uid_val);
			break;
		}
	}

	ldap_msgfree(vals);
	return uidnum;
}
