
#include <string.h>
#include <stdlib.h>
#include "sgx_tseal.h"
#include "Enclave_t.h"


void ecall_verify_user_pwd(uint8_t *auth_ret, sgx_sealed_data_t *p_sealed_data, uint32_t sealed_data_size, const char *username_entered, const char *password_entered, uint8_t nullok)
{
 
    /*Unsealing p_sealed_data*/
    uint32_t p_decripted_text_length = sgx_get_encrypt_txt_len(p_sealed_data);
    uint8_t *p_decripted_text;
    p_decripted_text = (uint8_t *)malloc(p_decripted_text_length);

    sgx_status_t result = sgx_unseal_data(p_sealed_data, NULL,0, p_decripted_text, &p_decripted_text_length);

    if (result != SGX_SUCCESS){
    
        if (result == SGX_ERROR_MAC_MISMATCH)
            ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_MAC_MISMATCH\n");
        else if (result == SGX_ERROR_UNEXPECTED)
            ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_UNEXPECTED\n");
        else if (result == SGX_ERROR_INVALID_PARAMETER)
            ocall_print_pointer((char*)"sgx_UNSEAL_data = SGX_ERROR_INVALID_PARAMETER\n");
        else
            ocall_print_pointer((char*)"sgx_UNSEAL_data = FALHOU\n");
    }
    char * pch;
    pch = strstr ((char*)p_decripted_text,username_entered);
    if (pch == NULL)
    {
        ocall_print_pointer((char*)"usuario nao existente\n");
        *auth_ret = 2;
        ocall_sleep();

    }else{

        /////////////
        char *auth_pair;
        auth_pair = (char*)malloc(sizeof(username_entered)+sizeof(password_entered)+2);
        strncpy(auth_pair,username_entered,sizeof(username_entered));
        strncat(auth_pair,":",1);
        strncat(auth_pair,password_entered,sizeof(password_entered));
        strncat(auth_pair,"\n",1);
        // ocall_print_pointer(auth_pair);

        pch = NULL;
        pch = strstr ((char*)p_decripted_text,auth_pair);
        if (pch == NULL)
        {
            *auth_ret = 0;
            ocall_sleep();

        }
        else{
            if (password_entered==NULL && !nullok)
            {
                *auth_ret = 0;
                ocall_sleep();

            }
            else
                *auth_ret = 1;
        }

        /////////////
    }
    password_entered = NULL; 



}


sgx_status_t ecall_seal_data(const char* fileName, void* data, int length){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
    uint32_t sealed_data_size;
    sgx_sealed_data_t *p_sealed_data;

    sealed_data_size = sgx_calc_sealed_data_size(0, length);

    p_sealed_data = (sgx_sealed_data_t*) malloc(sealed_data_size);

    ret = sgx_seal_data(0, NULL, length, (uint8_t*)data, sealed_data_size, p_sealed_data);

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