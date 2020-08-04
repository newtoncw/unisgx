#include <string.h>
#include <stdlib.h>
#include "sgx_tseal.h"
#include "sgx_report.h"
//#include "sgx_thread.h"
#include "sgx_spinlock.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "md5.h"
#include "Enclave_t.h" // Gerado pelo Edger8r

#define SESSION_COUNT 200

typedef struct _la_dh_session_t {
	sgx_enclave_id_t enclave_id;
	uint8_t status; //0 - closed; 1 - in progress; 2 - active
	sgx_dh_session_t dh_session;
	sgx_key_128bit_t session_dh_aek; //Session Key
} dh_session_t;

dh_session_t sessions[SESSION_COUNT];

uint8_t *p_decripted_text = NULL;

//sgx_thread_mutex_t lock;
sgx_spinlock_t lock = SGX_SPINLOCK_INITIALIZER;

static void strip_hpux_aging(char *hash) {
	static const char valid[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789./";

	if ((*hash != '$') && (strlen(hash) > 13)) {
		for (hash += 13; *hash != '\0'; hash++) {
			if (strchr(valid, *hash) == NULL) {
				*hash = '\0';
				break;
			}
		}
	}
}

sgx_dh_session_t *get_dh_session(sgx_enclave_id_t enclave_id) {
	for(int i = 0; i < SESSION_COUNT; i++) {
		if((sessions[i].enclave_id == enclave_id) && (sessions[i].status == 1)) {
			return &(sessions[i].dh_session);
		}
	}

	return NULL;
}

sgx_key_128bit_t *get_session_aek(sgx_enclave_id_t enclave_id) {
	for(int i = 0; i < SESSION_COUNT; i++) {
		if((sessions[i].enclave_id == enclave_id) && (sessions[i].status == 2)) {
			return &(sessions[i].session_dh_aek);
		}
	}

	return NULL;
}

void set_dh_session(sgx_enclave_id_t enclave_id, sgx_dh_session_t *dh_session) {
	//sgx_thread_mutex_lock(&lock);
	//sgx_spin_lock(&lock);

	for(int i = 0; i < SESSION_COUNT; i++) {
		if(sessions[i].enclave_id == 0) {
			sessions[i].enclave_id = enclave_id;
			sessions[i].status = 1;
			memcpy(&(sessions[i].dh_session), dh_session, sizeof(sgx_dh_session_t));
			break;
		}
	}

	//sgx_thread_mutex_unlock(&lock);
	//sgx_spin_unlock(&lock);
}

void set_session_aek(sgx_enclave_id_t enclave_id, sgx_key_128bit_t *session_dh_aek) {
	//sgx_thread_mutex_lock(&lock);
	//sgx_spin_lock(&lock);

	for(int i = 0; i < SESSION_COUNT; i++) {
		if((sessions[i].enclave_id == enclave_id) && (sessions[i].status == 1)) {
			sessions[i].status = 2;
			memcpy(&(sessions[i].session_dh_aek), session_dh_aek, sizeof(sgx_key_128bit_t));
			break;
		}
	}

	//sgx_thread_mutex_unlock(&lock);
	//sgx_spin_unlock(&lock);
}

void close_session(sgx_enclave_id_t enclave_id) {
	//sgx_thread_mutex_lock(&lock);
	//sgx_spin_lock(&lock);

	for(int i = 0; i < SESSION_COUNT; i++) {
		if(sessions[i].enclave_id == enclave_id) {
			sessions[i].enclave_id = 0;
			sessions[i].status = 0;
			break;
		}
	}

	//sgx_thread_mutex_unlock(&lock);
	//sgx_spin_unlock(&lock);
}

void ecall_unseal_data(sgx_sealed_data_t *p_sealed_data, uint32_t sealed_data_size) {
	uint32_t p_decripted_text_length = sgx_get_encrypt_txt_len(p_sealed_data);
	p_decripted_text = (uint8_t *)malloc(p_decripted_text_length);

	//sgx_thread_mutex_init(&lock, NULL);

	//sgx_thread_mutex_lock(&lock);
	//sgx_spin_lock(&lock);

	for(int i = 0; i < SESSION_COUNT; i++) {
		sessions[i].enclave_id = 0;
		sessions[i].status = 0;
	}

	//sgx_thread_mutex_unlock(&lock);
	//sgx_spin_unlock(&lock);

	sgx_status_t result = sgx_unseal_data(p_sealed_data, NULL,0, p_decripted_text, &p_decripted_text_length);

	if (result != SGX_SUCCESS) {
		if (result == SGX_ERROR_MAC_MISMATCH)
			ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_MAC_MISMATCH\n");
		else if (result == SGX_ERROR_UNEXPECTED)
			ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_UNEXPECTED\n");
		else if (result == SGX_ERROR_INVALID_PARAMETER)
			ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_INVALID_PARAMETER\n");
		else
			ocall_print_pointer((char*)"sgx_UNSEAL_data = FALHOU\n");
	} // else{
		// ocall_print_pointer((char*)"O arquivo deselado eh:\n\"\n");
		// ocall_print_pointer((char*)p_decripted_text);
		// ocall_print_pointer((char*)"\"\n");
	// }
}

void ecall_verify_user_pwd(sgx_enclave_id_t enclave_id, sgx_aes_gcm_data_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size) {
	char p_dest[message->payload_size], p_ret[3];
	sgx_status_t status;
	uint8_t auth_ret;
	sgx_key_128bit_t *session_dh_aek = get_session_aek(enclave_id);

	status = sgx_rijndael128GCM_decrypt(session_dh_aek, message->payload, message->payload_size, p_dest, message->reserved, sizeof(message->reserved), NULL, 0, &(message->payload_tag));

	uint8_t nullok, len;
	char *username_entered, *password_entered, *tmp, *tmp2, *user_tmp;

	//ocall_print_pointer(p_dest);
	//ocall_print_pointer((char*)"\n");

	// user name
	tmp = strchr(p_dest, '$');
	len = tmp - p_dest;
	username_entered = malloc(len + 10);
	strncpy(username_entered, p_dest, len);
	username_entered[len] = '\0';
	//ocall_print_pointer(username_entered);
	//ocall_print_pointer((char*)"\n");

	// password
	tmp2 = strchr(tmp + 1, '$');
	len = tmp2 - tmp;
	password_entered = malloc(len + 10);
	strncpy(password_entered, tmp + 1, len - 1);
	password_entered[len - 1] = '\0';
	//ocall_print_pointer(password_entered);
	//ocall_print_pointer((char*)"\n");

	// ctrl
	if (p_dest[strlen(p_dest) - 1] == '1') {
		nullok = 1;
	} else {
		nullok = 0;
	}

	user_tmp = (char*)malloc(strlen(username_entered) + 3);
	strncpy(user_tmp, "\n\0", 2);
	strncat(user_tmp, username_entered, strlen(username_entered));
	strncat(user_tmp, ":\0", 2);

	//ocall_print_pointer(user_tmp);
	//ocall_print_pointer((char*)"\n");

	char *hash = (char*)malloc(sizeof("$1$ctvYvBSZ$iADgBulVBa5tm7ZMbQALX0") + 2);
	char *user;

	user = strstr((char*)p_decripted_text, user_tmp); //retorna um ponteiro para o inicio da linha contendo as info de usuario
	if (user == NULL) {
		ocall_print_pointer((char*)"usuario nao existente\n");
		auth_ret = 2;
		ocall_sleep();
	} else {
		strncpy(hash, (user + strlen(user_tmp)), sizeof("$1$ctvYvBSZ$iADgBulVBa5tm7ZMbQALX0") - 1); // copia o hash contido no arquivo de senhas
		hash[34] = '\0';
		// ocall_print_pointer((char*)"hash:");
		// ocall_print_pointer((char*)hash);
		// ocall_print_pointer((char*)"\n");

		/////////////////////int verify_pwd_hash(const char *p, char *hash, unsigned int nullok)
		size_t hash_len;
		char *pp = NULL;
		int retval;
		// D(("called"));

		strip_hpux_aging(hash);
		hash_len = strlen(hash);
		if (!hash_len) {
			// the stored password is NULL
			if (nullok) { // this means we've succeeded 
				// D(("user has empty password - access granted"));
				auth_ret = 1;
			} else {
				// D(("user has empty password - access denied"));
				auth_ret = 0;
				ocall_print_pointer((char*)"user has empty password - access denied\n");
				ocall_sleep();
			}
		} else if (!password_entered || *hash == '*' || *hash == '!') {
			auth_ret = 0;
			ocall_print_pointer((char*)"no password\n");
			ocall_sleep();
		} else {
			// ocall_print_pointer((char*)"hash:");
			// ocall_print_pointer(hash);
			// ocall_print_pointer((char*)"\n");

			if (!strncmp(hash, "$1$", 3)) {
				pp = Goodcrypt_md5(password_entered, hash);

				if (pp && strcmp(pp, hash) != 0) {
					// _pam_delete(pp);
					pp = Goodcrypt_md5(password_entered, hash);
				}
			} else {
				//  Ok, we don't know the crypt algorithm, but maybe libcrypt knows about it? We should try it.
				ocall_print_pointer((char*)"Algoritmo de hash de senha nao suportado\n");
				auth_ret = 0;
				ocall_sleep();
			}

			password_entered = NULL;       // no longer needed here 

			// the moment of truth -- do we agree with the password? 
			// D(("comparing state of pp[%s] and hash[%s]", pp, hash));

			if (pp && strcmp(pp, hash) == 0) {
				auth_ret = 1;
				//ocall_print_pointer((char*)"hash ok\n");
				//ocall_print_pointer(hash);
				//ocall_print_pointer((char*)" - ");
				//ocall_print_pointer(pp);
				//ocall_print_pointer((char*)"\n");
				// ocall_print_pointer(pp);
			} else {
				auth_ret = 0;
				ocall_print_pointer((char*)"hash error\n");
				//ocall_print_pointer(hash);
				//ocall_print_pointer((char*)" - ");
				//ocall_print_pointer(pp);
				//ocall_print_pointer((char*)" - ");
				//ocall_print_pointer(password_entered);
				//ocall_print_pointer((char*)"\n");
				ocall_sleep();
			}
		}

		// if (pp)
			// _pam_delete(pp);
		// D(("done [%d].", retval));

		free(pp);
	}

	p_ret[0] = auth_ret + 48;
	p_ret[1] = p_ret[0];
	p_ret[2] = p_ret[0];
	response->payload_size = 3;
	status = sgx_rijndael128GCM_encrypt(session_dh_aek, (uint8_t*)p_ret, 3, response->payload, response->reserved, sizeof(response->reserved), NULL, 0, &(response->payload_tag));
	//ocall_print_int(sizeof(*response));

	//ocall_print_pointer(p_ret);
	//ocall_print_pointer((char*)"\n");

	free(user_tmp);
	free(hash);

	close_session(enclave_id);
}

sgx_status_t ecall_seal_data(const char* fileName, void* data, int length) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED, retval = SGX_ERROR_UNEXPECTED;
	uint32_t sealed_data_size;
	sgx_sealed_data_t *p_sealed_data;

	sealed_data_size = sgx_calc_sealed_data_size(0, length);

	p_sealed_data = (sgx_sealed_data_t*) malloc(sealed_data_size);

	ret = sgx_seal_data(0, NULL, length, data, sealed_data_size, (sgx_sealed_data_t*)p_sealed_data);

	if (ret == SGX_SUCCESS) {
		ret = save_data(&retval, fileName, p_sealed_data, sealed_data_size);
	}

	free(p_sealed_data);

	return ret;
}

void ecall_session_request(sgx_enclave_id_t enclave_id, sgx_dh_msg1_t *dh_msg1) {
	//sgx_spin_lock(&lock);

	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_session_t sgx_dh_session;

	//ocall_print("ecall_session_request");

	if(!dh_msg1) {
		ocall_print("dh_msg1 INVALIDA!");
		//sgx_spin_unlock(&lock);
		return;
	}

	//ocall_print("Enclave 2 sgx_dh_init_session");
	status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
	if(status != SGX_SUCCESS) {
		ocall_print("ecall_session_request 1 ERRO!");
		ocall_print_int(status);
		//sgx_spin_unlock(&lock);
		return;
	}

	//ocall_print("Enclave 2 sgx_dh_responder_gen_msg1");
	status = sgx_dh_responder_gen_msg1(dh_msg1, &sgx_dh_session);
	if(status != SGX_SUCCESS) {
		ocall_print("ecall_session_request 2 ERRO!");
		ocall_print_int(status);
		//sgx_spin_unlock(&lock);
		return;
	}

	//ocall_print("saving session");

	set_dh_session(enclave_id, &sgx_dh_session);

	//ocall_print("ecall_session_request OK");

	//sgx_spin_unlock(&lock);
}

void ecall_exchange_report(sgx_enclave_id_t enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, sgx_key_128bit_t *dh_aek) {
	//sgx_spin_lock(&lock);

	sgx_dh_session_enclave_identity_t initiator_identity;
	sgx_dh_session_t *sgx_dh_session = get_dh_session(enclave_id);

	if(sgx_dh_session == NULL) {
		ocall_print("ecall_exchange_report SESSION NULL!");
		return;
	}

	//ocall_print("Enclave 2 sgx_dh_responder_proc_msg2");
	sgx_status_t status = sgx_dh_responder_proc_msg2(dh_msg2, dh_msg3, sgx_dh_session, dh_aek, &initiator_identity);
	if(status != SGX_SUCCESS) {
		ocall_print("ecall_exchange_report ERRO!");
		ocall_print_int(status);
		//sgx_spin_unlock(&lock);
		return;
	}

	//memcpy(&session_dh_aek, dh_aek, sizeof(sgx_key_128bit_t));
	set_session_aek(enclave_id, dh_aek);

	//sgx_spin_unlock(&lock);
}
