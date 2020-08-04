######### SGX TOOLS ######################
SGX_SDK ?= /opt/Intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

######## App Settings ########
App_C_Flags := -fPIC -Wno-attributes -IInclude -IApp -I$(SGX_SDK)/include
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts -lpthread -lsgx_uae_service

######## Enclave Settings ########
Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector -IInclude -IEnclave \
	-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

.PHONY: all run

all: $(Signed_Enclave_Name) pam_test_n.so app_sgx auth_test

run: all


######## App Objects ########
App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

App/Enclave_u.o: App/Enclave_u.c
	gcc $(App_C_Flags) -c $< -o $@ -g

App/Lib_ocalls.o: App/Lib_ocalls.c
	gcc $(App_C_Flags) -c $< -o $@ -g
	
App/pam_sgx.o: App/pam_sgx.c
	gcc $(App_C_Flags) -c $< -o $@ -g 

App/App.o: App/App.c
	gcc $(App_C_Flags) -c $< -o $@ -g

App/md5.o: App/md5.c
	gcc $(App_C_Flags) -c $< -o $@ -g

App/bigcrypt.o: App/bigcrypt.c
	gcc $(App_C_Flags) -c $< -o $@ -g

App/support.o: App/support.c
	gcc $(App_C_Flags) -c $< -o $@ -g

App/passverify.o: App/passverify.c
	gcc $(App_C_Flags) -c $< -o $@ -g

App/pam_test_n.o: App/pam_unix_auth.c
	gcc $(App_C_Flags) -c $< -o $@ -g

pam_test_n.so: App/Enclave_u.o App/pam_test_n.o App/support.o App/passverify.o App/bigcrypt.o App/md5.o App/Lib_ocalls.o
	gcc $^ -shared -o /lib/x86_64-linux-gnu/security/$@ -lpam -lcrypt $(App_Link_Flags) -g

app_sgx: App/Enclave_u.o App/App.o App/Lib_ocalls.o
	gcc $^ -o $@ -lpam $(App_Link_Flags) -g

auth_test: auth_test.c
	gcc $^ -o $@ -lpam -lpam_misc

####### Enclave Objects ########
Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

Enclave/Enclave_t.o: Enclave/Enclave_t.c 
	gcc $(Enclave_C_Flags) -c $< -o $@ -g

Enclave/Lib_ecalls.o: Enclave/Lib_ecalls.c
	gcc $(Enclave_C_Flags) -c $< -o $@ -g

Enclave/md5.o: Enclave/md5.c
	gcc $(Enclave_C_Flags) -c $< -o $@ -g

$(Enclave_Name): Enclave/Enclave_t.o Enclave/Lib_ecalls.o Enclave/md5.o
	gcc $^ -o $@ $(Enclave_Link_Flags) -g

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out /lib/x86_64-linux-gnu/security/$@ -config $(Enclave_Config_File)


.PHONY: clean

clean:
	@rm -f $(Enclave_Name) Enclave/*.o App/Enclave_u.* Enclave/Enclave_t.* App/*.o /lib/x86_64-linux-gnu/security/enclave.signed.so app_sgx auth_test sealed_shadow /lib/x86_64-linux-gnu/security/pam_test_n.so

