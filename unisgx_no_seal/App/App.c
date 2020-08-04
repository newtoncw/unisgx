#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "sgx_eid.h"     /* sgx_enclave_id_t Estah pegando de outro lugar via source...*/
#include "sgx_tseal.h"     /* sgx_enclave_id_t Estah pegando de outro lugar via source...*/ //home/pamsgx/Documents/linux-sgx-master/linux/installer/bin/sgxsdk/include/
#include "Enclave_u.h" // generated by sgx_edger8r

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "/lib/x86_64-linux-gnu/security/enclave.signed.so"
# define MAX_PATH FILENAME_MAX

# define SHADOW_ "/home/rafael/pam_sgx_tests_v1/unix_sgx_noseal/shadow"
# define SEALED_SHADOW "/home/rafael/pam_sgx_tests_v1/unix_sgx_noseal/sealed_shadow"


int main(int argc, char *argv[])
{

    printf("Este App prepara o ambiente para a autenticacao via modulo PAM_SGX\n"); 

    /* Initialize the enclave */
    char token_path[MAX_PATH] = {'\0'};
    sgx_enclave_id_t global_eid = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;

    int updated = 0;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("ERRO %d na inicializacao do enclave ...\n\n", ret); 
    }
    else{
        printf("Enclave Inicializado com sucesso!\n"); 


    FILE * myfile;
    myfile = fopen(SHADOW_,"rb");
    fseek(myfile, 0, SEEK_END);
    long file_length = ftell(myfile);
    fseek(myfile, 0, SEEK_SET);
    uint8_t *file_data;
    file_data = (uint8_t*)malloc(file_length);
    fread(file_data, sizeof(uint8_t), file_length, myfile);
    fclose(myfile);
    printf("Arquivo %s carregado...\n", SHADOW_);
    ret = ecall_seal_data(global_eid, &retval,SEALED_SHADOW ,file_data, file_length);
    printf("Arquivo %s gerado...\n", SEALED_SHADOW);


    }

    sgx_destroy_enclave(global_eid);

    return 0;
    
}

