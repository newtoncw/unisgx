# UniSGX Prototypes

## Using Intel SGX to Protect Authentication Credentials in an Untrusted Operating System

Source code of the prototype presented in the paper [Using Intel SGX to Protect Authentication Credentials in an Untrusted Operating System](https://ieeexplore.ieee.org/document/8538470), presented at [23th IEEE Symposium on Computers and Communications (ISCC 2018)](https://iscc2018.ieee-iscc.org).

### Abstract
We present a novel password file protection scheme, which uses Intel SGX to protect authentication credentials in the PAM authentication framework, commonly used in UNIX systems. We defined and implemented an SGX-enabled version of the pam_unix.so authentication module, called UniSGX. This module uses an SGX enclave to handle the credentials informed by the user and to check them against the password file. To add an extra security layer, the password file is stored using SGX sealing. Different scenarios were implemented to evaluate the overhead posed by protected memory, sealed file, and the overall overhead:

### Sources
- [UniSGX no seal](https://github.com/newtoncw/unisgx/tree/master/unisgx_no_seal): The authentication is done inside the enclave, but the original unprotected credentials file is used.

- [UniSGX](https://github.com/newtoncw/unisgx/tree/master/unisgx): Runs the UniSGX module prototype, including enclave instantiation, sealed data, and hashed passwords.

- [UniSGX no hash](https://github.com/newtoncw/unisgx/tree/master/unisgx_no_hash): Runs the UniSGX module prototype, including enclave instantiation, sealed data, but using a credentials file with unhashed passwords.

## Using a Shared SGX Enclave in the UNIX PAM Authentication Service

Source code of the prototype presented in the paper [Using a Shared SGX Enclave in the UNIX PAM Authentication Service](https://2020.ieeesyscon.org), presented at [14th Annual IEEE International Systems Conference (SysCon 2020)](https://2020.ieeesyscon.org).

### Abstract
Using SGX enclaves usually incurs in a performance impact in the application execution. We propose an enclave sharing approach to reduce the performance overhead in scenarios where multiple enclaves handle the same data. To evaluate this approach, we implemented a SGX-secured OS authentication service. Three prototypes were built, considering distinct concerns about security and performance.

### Sources
- [UniSGX Authentication Service with Hard-coded AES Keys](https://github.com/newtoncw/unisgx/tree/master/unisgx_auth_server_hard_aes): The encryption key is hard-coded in the client and the enclave, and creates a secure communication channel between the client and the enclave.

- [UniSGX Authentication Service with ECDH Key Agreement](https://github.com/newtoncw/unisgx/tree/master/unisgx_auth_server_ecdh_agreement): A session key for communication is defined by an Elliptic-Curve Diffie–Hellman (ECDH) key agreement scheme based on Curve25519.

- [UniSGX Authentication Service with Attestation](https://github.com/newtoncw/unisgx/tree/master/unisgx_auth_server_attestation): SGX local attestation is used to verify whether the UniSGX client process is running in the same platform as the server process.

If you make nay use of this code for academic purpose, please cite the paper.
