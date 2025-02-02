/*
 * Copyright Alexander O. Yuriev, 1996.  All rights reserved.
 * NIS+ support by Thorsten Kukuk <kukuk@weber.uni-paderborn.de>
 * Copyright Jan RÍkorajski, 1999.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <time.h>/////
#define BILLION  1000000.0
#define COUNTTIME 0

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

/* indicate the following groups are defined */

#ifdef PAM_STATIC
# include "pam_unix_static.h"
#else
# define PAM_SM_AUTH
#endif

#define _PAM_EXTERN_FUNCTIONS
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "support.h"

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */

/* Fun starts here :)

 * pam_sm_authenticate() performs UNIX/shadow authentication
 *
 *      First, if shadow support is available, attempt to perform
 *      authentication using shadow passwords. If shadow is not
 *      available, or user does not have a shadow password, fallback
 *      onto a normal UNIX authentication
 */

#define _UNIX_AUTHTOK  "-UN*X-PASS"

#define AUTH_RETURN						\
do {								\
	if (on(UNIX_LIKE_AUTH, ctrl) && ret_data) {		\
		D(("recording return code for next time [%d]",	\
					retval));		\
		*ret_data = retval;				\
		pam_set_data(pamh, "unix_setcred_return",	\
		             (void *) ret_data, setcred_free);	\
	} else if (ret_data)					\
	  free (ret_data);                                      \
	D(("done. [%s]", pam_strerror(pamh, retval)));		\
	return retval;						\
} while (0)


static void
setcred_free (pam_handle_t *pamh UNUSED, void *ptr, int err UNUSED)
{
	if (ptr)
		free (ptr);
}

void write_time(double time) {
	FILE *fp = fopen("/home/newton/time.txt", "a+");

	if(fp != NULL) {
		fprintf(fp, "%lf\n", time);

		fclose(fp);
	}
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	struct timespec start, stop;
	double accum[3];
	
	#if COUNTTIME
	printf("Iniciando autenticacao\n");
 	
	if(clock_gettime(CLOCK_REALTIME, &start) == -1) {
		perror("clock gettime");
		exit(EXIT_FAILURE);
	}
	#endif

	unsigned int ctrl;
	int retval, *ret_data = NULL;
	const char *name;
	const void *p;

	D(("called."));

	ctrl = _set_ctrl(pamh, flags, NULL, NULL, NULL, argc, argv);

	/* Get a few bytes so we can pass our return value to
	   pam_sm_setcred(). */
	if (on(UNIX_LIKE_AUTH, ctrl))
		ret_data = malloc(sizeof(int));

	#if COUNTTIME
	/* get the user'name' */
	if(clock_gettime(CLOCK_REALTIME, &stop) == -1) {
		perror("clock gettime");
		exit(EXIT_FAILURE);
	}

	accum[0] = (double)(stop.tv_sec - start.tv_sec) * 1.0e9 + (double)(stop.tv_nsec - start.tv_nsec);
	//if(accum[0] < 0) accum[0] = 0;
	#endif

	retval = pam_get_user(pamh, &name, NULL);

	#if COUNTTIME
	if(clock_gettime(CLOCK_REALTIME, &start) == -1) {
		perror("clock gettime");
		exit(EXIT_FAILURE);
	}
	#endif

	if (retval == PAM_SUCCESS) {
		/*
		 * Various libraries at various times have had bugs related to
		 * '+' or '-' as the first character of a user name. Don't
		 * allow this characters here.
		 */
		if (name == NULL || name[0] == '-' || name[0] == '+') {
			pam_syslog(pamh, LOG_ERR, "bad username [%s]", name);
			retval = PAM_USER_UNKNOWN;
			AUTH_RETURN;
		}
		if (on(UNIX_DEBUG, ctrl))
			D(("username [%s] obtained", name));
	} else {
		D(("trouble reading username"));
		if (retval == PAM_CONV_AGAIN) {
			D(("pam_get_user/conv() function is not ready yet"));
			/* it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
		AUTH_RETURN;
	}

	/* if this user does not have a password... */

	if (_unix_blankpasswd(pamh, ctrl, name)) {
		D(("user '%s' has blank passwd", name));
		name = NULL;
		retval = PAM_SUCCESS;
		AUTH_RETURN;
	}
	/* get this user's authentication token */

	#if COUNTTIME
	if(clock_gettime(CLOCK_REALTIME, &stop) == -1) {
		perror("clock gettime");
		exit(EXIT_FAILURE);
	}

	accum[1] = (double)(stop.tv_sec - start.tv_sec) * 1.0e9 + (double)(stop.tv_nsec - start.tv_nsec);
        //if(accum[1] < 0) accum[1] = 0;
	#endif

	retval = _unix_read_password(pamh, ctrl, NULL, _("Password: "), NULL, _UNIX_AUTHTOK, &p);
 
	#if COUNTTIME
	if(clock_gettime(CLOCK_REALTIME, &start) == -1) {
		perror("clock gettime");
		exit(EXIT_FAILURE);
	}
	#endif

	if (retval != PAM_SUCCESS) {
		if (retval != PAM_CONV_AGAIN) {
			pam_syslog(pamh, LOG_CRIT,
			    "auth could not identify password for [%s]", name);
		} else {
			D(("conversation function is not ready yet"));
			/*
			 * it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
		name = NULL;
		AUTH_RETURN;
	}
	D(("user=%s, password=[%s]", name, p));

	/* verify the password of this user */
	retval = _unix_verify_password(pamh, name, p, ctrl);
	name = p = NULL;

	#if COUNTTIME
	if(clock_gettime(CLOCK_REALTIME, &stop) == -1) {
		perror("clock gettime");
		exit(EXIT_FAILURE);
	}

	accum[2] = (double)(stop.tv_sec - start.tv_sec) * 1.0e9 + (double)(stop.tv_nsec - start.tv_nsec);
	//if(accum[2] < 0) accum[2] = 0;
	double Tempo = (accum[0] + accum[1] + accum[2]) / 1.0e6;/////
	
	printf("unix_sgx - Tempo: %g ms.\n", Tempo);/////
	write_time(Tempo);
	#endif
    
	AUTH_RETURN;
}


/*
 * The only thing _pam_set_credentials_unix() does is initialization of
 * UNIX group IDs.
 *
 * Well, everybody but me on linux-pam is convinced that it should not
 * initialize group IDs, so I am not doing it but don't say that I haven't
 * warned you. -- AOY
 */

int
pam_sm_setcred (pam_handle_t *pamh, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
	int retval;
	const void *pretval = NULL;

	D(("called."));

	retval = PAM_SUCCESS;

	D(("recovering return code from auth call"));
	/* We will only find something here if UNIX_LIKE_AUTH is set --
	   don't worry about an explicit check of argv. */
	if (pam_get_data(pamh, "unix_setcred_return", &pretval) == PAM_SUCCESS
	    && pretval) {
	        retval = *(const int *)pretval;
		pam_set_data(pamh, "unix_setcred_return", NULL, NULL);
		D(("recovered data indicates that old retval was %d", retval));
	}

	return retval;
}
