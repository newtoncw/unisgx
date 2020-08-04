#include "sgx_eid.h"
#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"
#include "stdlib.h"
#include "string.h"
#include "ClientEnclave_t.h" // Gerado pelo Edger8r

sgx_status_t create_session(sgx_enclave_id_t enclave_id, sgx_key_128bit_t *session_dh_aek) {
	sgx_status_t status = SGX_SUCCESS;
	sgx_key_128bit_t dh_aek;
	sgx_dh_msg1_t dh_msg1;  //Diffie-Hellman Message 1
	sgx_dh_msg2_t dh_msg2;  //Diffie-Hellman Message 2
	sgx_dh_msg3_t dh_msg3;  //Diffie-Hellman Message 3
	sgx_dh_session_enclave_identity_t responder_identity;
	sgx_dh_session_t sgx_dh_session;

	//ocall_print("sgx_dh_init_session");
	status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
	if(status != SGX_SUCCESS) {
		return status;
	}

	//ocall_print("ocall_session_request");
	status = ocall_session_request(enclave_id, &dh_msg1);
	if (status != SGX_SUCCESS) {
		return status;
	}

	//ocall_print("sgx_dh_initiator_proc_msg1");
	status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
	if (status != SGX_SUCCESS) {
		return status;
	}

	//ocall_print("ocall_exchange_report");
	status = ocall_exchange_report(enclave_id, &dh_msg2, &dh_msg3, &dh_aek);
	if (status != SGX_SUCCESS) {
		return status;
	}

	//ocall_print("sgx_dh_initiator_proc_msg3");
	status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
	if (status != SGX_SUCCESS) {
		return status;
	}

	memcpy(session_dh_aek, dh_aek, sizeof(sgx_key_128bit_t));

	return SGX_SUCCESS;
}

void ecall_send_message(sgx_enclave_id_t enclave_id, uint8_t *auth_ret, const char *name, const char *password, unsigned int ctrl) {
	sgx_status_t status;

	char *message = malloc(strlen(name) + strlen(password) + 10);
	strncpy(message, name, strlen(name));
	strncat(message, "$\0", 2);
	strncat(message, password, strlen(password));
	strncat(message, "$\0", 2);
	if (ctrl) {
		strncat(message, "1\0", 2);
	} else {
		strncat(message, "0\0", 2);
	}

	uint32_t src_len = strlen(message);
	sgx_aes_gcm_data_t* secure_message;
	size_t message_size;
	sgx_key_128bit_t session_dh_aek;

	//ocall_print("create_session");
	status = create_session(enclave_id, &session_dh_aek);
	if(status != SGX_SUCCESS) {
		ocall_print("Enclave1_create_session ERRO");
		return;
	}

	message_size = sizeof(sgx_aes_gcm_data_t) + src_len;
	secure_message = (sgx_aes_gcm_data_t*)malloc(message_size);
	secure_message->payload_size = src_len;

	status = sgx_rijndael128GCM_encrypt(&session_dh_aek, (uint8_t*)message, src_len, secure_message->payload, secure_message->reserved, sizeof(secure_message->reserved), NULL, 0, &(secure_message->payload_tag));
	if(status != SGX_SUCCESS) {
		ocall_print("sgx_rijndael128GCM_encrypt ERRO");
		return;
	}

	sgx_aes_gcm_data_t* response;
	size_t response_size = sizeof(sgx_aes_gcm_data_t) + 3;
	uint8_t error = 0;

	response = (sgx_aes_gcm_data_t*)malloc(response_size);
	response->payload_size = 3;
	//ocall_print_int(response_size);

	status = ocall_send_request(enclave_id, secure_message, message_size, response, response_size, &error);
	if(status != SGX_SUCCESS) {
		ocall_print("ERRO ao enviar mensagem");
		return;
	}

	//ocall_print_int(error);
	//ocall_print_int(response->payload_size);
	char p_dest[response->payload_size];
	//ocall_print_int(sizeof(sgx_aes_gcm_data_t) + 3);

	if(error == 0) {
		status = sgx_rijndael128GCM_decrypt(&session_dh_aek, response->payload, response->payload_size, p_dest, response->reserved, sizeof(response->reserved), NULL, 0, &(response->payload_tag));

		//ocall_print(p_dest);

		if(status == SGX_SUCCESS) {
			*auth_ret = p_dest[0] - 48;
		} else if(status == 1) {
			*auth_ret = 0;
		} else {
			*auth_ret = status;
		}
	} else if(error == 1) {
		*auth_ret = 0;
	} else {
		*auth_ret = error;
	}

	//ocall_print_int(*auth_ret);
}
