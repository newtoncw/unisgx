//gcc -o auth_test auth_test.c -lpam -lpam_misc
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <string.h>

struct pam_response *reply;

//function used to get user input
int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
	*resp = reply;
	return PAM_SUCCESS;
}

int authenticate_system(const char *user, const char *password) {
	pam_handle_t* pamh = NULL;
	int retval;
	const char* service_name = "auth_test";
	const struct pam_conv pam_conversation = { function_conversation, NULL };

	retval = pam_start(service_name, user, &pam_conversation, &pamh);

	if (retval == PAM_SUCCESS) {
		reply = (struct pam_response*)malloc(sizeof(struct pam_response));

		// *** Get the password by any method, or maybe it was passed into this function.
		reply[0].resp = strdup(password);
		reply[0].resp_retcode = 0;

		retval = pam_authenticate(pamh, 0);
	} else {
		printf("Aplicacao: Falha no pam_start()!\n");
	}

	if (retval == PAM_SUCCESS) {
		printf("Aplicacao: Autenticado!\n");
	} else {
		printf("Aplicacao: Falha de autenticacao!\n");
	}

	/*if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("Aplicacao: Falha no pam_end()\n");
		return 1;
	}*/

	//free(reply);

	return retval == PAM_SUCCESS ? 0 : 1;
}

int main(int argc, char *argv[]) {
	int i, num = atoi(argv[3]);

	printf("\nAplicacao: Inicio!\n");

	for(i = 0; i < num; i++) {
		printf("Tentativa %d - ", i + 1);
		authenticate_system(argv[1], argv[2]);
		printf("Fim tentativa\n");
	}

	printf("Aplicacao: Fim!\n");
}
