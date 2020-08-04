#include <string.h>
#include <stdlib.h>
#include "sgx_tseal.h"
#include "md5.h"
#include "Enclave_t.h" // Gerado pelo Edger8r
#include "aes.h"

uint8_t *p_decripted_text;
uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
	struct AES_ctx ctx;

	memcpy(ciphertext, plaintext, plaintext_len);
    
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, ciphertext, plaintext_len);

	return plaintext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
	return encrypt(ciphertext, ciphertext_len, plaintext);
}

void ecall_unseal_data(sgx_sealed_data_t *p_sealed_data, uint32_t sealed_data_size) {
	uint32_t p_decripted_text_length = sgx_get_encrypt_txt_len(p_sealed_data);
	p_decripted_text = (uint8_t *)malloc(p_decripted_text_length);

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

void ecall_verify_user_pwd(char *auth_ret, int auth_len, const char *username_entered, int username_len, const char *password_entered, int password_len, const char *nullok, int nullok_len) {
	char *user_tmp;
	char name[128], password[128], cnullok[128], cresponse[128];
	int ciphername_len, cipherpassword_len, ret_len;

	ret_len = decrypt((unsigned char*)username_entered, username_len, name);
	ret_len = decrypt((unsigned char*)password_entered, password_len, password);

	//ocall_print_pointer((char*)name);
	//ocall_print_pointer((char*)"\n");
	//ocall_print_pointer((char*)password);
	//ocall_print_pointer((char*)"\n");

	user_tmp = (char*)malloc(strlen(name) + 3);
	strncpy(user_tmp, "\n\0", 2);
	strncat(user_tmp, name, strlen(name));
	strncat(user_tmp, ":\0", 2);

	char *hash = (char*)malloc(sizeof("$1$ctvYvBSZ$iADgBulVBa5tm7ZMbQALX0"));
	char *user;

	user = strstr((char*)p_decripted_text, user_tmp); //retorna um ponteiro para o inicio da linha contendo as info de usuario
	if (user == NULL) {
		ocall_print_pointer((char*)"usuario nao existente\n");
		*auth_ret = 2;
		ocall_sleep();
	} else {
		strncpy(hash, (user + strlen(user_tmp)), sizeof("$1$ctvYvBSZ$iADgBulVBa5tm7ZMbQALX0") - 1); // copia o hash contido no arquivo de senhas
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
				*auth_ret = 1;
			} else {
				// D(("user has empty password - access denied"));
				*auth_ret = 0;
				ocall_sleep();
			}
		} else if (!password || *hash == '*' || *hash == '!') {
			*auth_ret = 0;
			ocall_sleep();
		} else {
			// ocall_print_pointer((char*)"hash:");
			// ocall_print_pointer(hash);
			// ocall_print_pointer((char*)"\n");

			if (!strncmp(hash, "$1$", 3)) {
				pp = Goodcrypt_md5(password, hash);

				if (pp && strcmp(pp, hash) != 0) {
					// _pam_delete(pp);
					pp = Goodcrypt_md5(password, hash);
				}
			} else {
				//  Ok, we don't know the crypt algorithm, but maybe libcrypt knows about it? We should try it.
				ocall_print_pointer((char*)"Algoritmo de hash de senha nao suportado\n");
				*auth_ret = 0;
				ocall_sleep();
			}

			//password = NULL;       // no longer needed here 

			// the moment of truth -- do we agree with the password? 
			// D(("comparing state of pp[%s] and hash[%s]", pp, hash));

			if (pp && strcmp(pp, hash) == 0) {
				*auth_ret = 1;
				// ocall_print_pointer(pp);
			} else {
				*auth_ret = 0;
				ocall_sleep();
			}
		}

		// if (pp)
			// _pam_delete(pp);
		// D(("done [%d].", retval));

		free(pp);
	}

	switch(*auth_ret) {
		case 2:
			auth_len = encrypt("2", 1, auth_ret);
			break;
		case 1:
			auth_len = encrypt("1", 1, auth_ret);
			break;
		default:
			auth_len = encrypt("0", 1, auth_ret);
	}

	free(user_tmp);
	free(hash);
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

// void ecall_authenticate(uint8_t *auth_ret, sgx_sealed_data_t *p_sealed_data, uint32_t sealed_data_size, const char *username_entered, const char *password_entered)
// {
//  ocall_print_pointer((char*)"ENTRANDO na ecall_authenticate\n"); 
//      ocall_print_pointer((char*)username_entered);
//     ocall_print_pointer((char*)"\n"); 
//     ocall_print_pointer((char*)password_entered);
//     ocall_print_pointer((char*)"\n"); 

//  ///*Unsealing p_sealed_data*/
//     uint32_t p_decripted_text_length = sgx_get_encrypt_txt_len(p_sealed_data);
//     uint8_t *p_decripted_text;
//     p_decripted_text = (uint8_t *)malloc(p_decripted_text_length);

//     sgx_status_t result = sgx_unseal_data(p_sealed_data, NULL,0, p_decripted_text, &p_decripted_text_length);

//     if (result == SGX_SUCCESS)
//     {
//         ocall_print_pointer((char*)"O arquivo deselado eh:\n\"\n");
//         ocall_print_pointer((char*)p_decripted_text);
//         ocall_print_pointer((char*)"\"\n");

//     }
//     else if (result == SGX_ERROR_MAC_MISMATCH)
//         ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_MAC_MISMATCH\n");
//     else if (result == SGX_ERROR_UNEXPECTED)
//         ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_UNEXPECTED\n");
//     else if (result == SGX_ERROR_INVALID_PARAMETER)
//         ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_INVALID_PARAMETER\n");
//     else
//         ocall_print_pointer((char*)"sgx_UNSEAL_data = FALHOU\n");
//     ocall_print_pointer((char*)"\nSAINDO da ecall_authenticate\n"); 
//     ///*END of Unsealing p_sealed_data*/



//     /////////////
//      char *auth_pair;
//      auth_pair = (char*)malloc(sizeof(username_entered)+sizeof(password_entered)+2);
//      strncpy(auth_pair,username_entered,sizeof(username_entered));
//      strncat(auth_pair,":",1);
//      strncat(auth_pair,password_entered,sizeof(password_entered));
//      strncat(auth_pair,"\n",1);
//      ocall_print_pointer(auth_pair);

//     char * pch;
//     pch = strstr ((char*)p_decripted_text,auth_pair);
//     if (pch == NULL)
//     {
//      *auth_ret = 0;
//     }
//     else
//      *auth_ret = 1;

//     /////////////

// }
