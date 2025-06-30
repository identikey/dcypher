#ifndef OPENFHE_WRAPPER_H
#define OPENFHE_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque types for C interface
typedef void* openfhe_cryptocontext_t;
typedef void* openfhe_keypair_t;
typedef void* openfhe_publickey_t;
typedef void* openfhe_privatekey_t;
typedef void* openfhe_ciphertext_t;
typedef void* openfhe_plaintext_t;
typedef void* openfhe_reencryptionkey_t;

// Crypto context management
openfhe_cryptocontext_t* openfhe_gen_cryptocontext_bfv(
    int plaintextModulus,
    int securityLevel,
    float distributionParameter,
    int maxDepth
);

void openfhe_cryptocontext_destroy(openfhe_cryptocontext_t* ctx);

int openfhe_cryptocontext_enable_pke(openfhe_cryptocontext_t* ctx);
int openfhe_cryptocontext_enable_keyswitch(openfhe_cryptocontext_t* ctx);
int openfhe_cryptocontext_enable_leveledshe(openfhe_cryptocontext_t* ctx);
int openfhe_cryptocontext_enable_pre(openfhe_cryptocontext_t* ctx);

// Key generation
openfhe_keypair_t* openfhe_keygen(openfhe_cryptocontext_t* ctx);
void openfhe_keypair_destroy(openfhe_keypair_t* keypair);

openfhe_publickey_t* openfhe_keypair_get_publickey(openfhe_keypair_t* keypair);
openfhe_privatekey_t* openfhe_keypair_get_privatekey(openfhe_keypair_t* keypair);

// Encryption/Decryption
openfhe_plaintext_t* openfhe_make_packed_plaintext(openfhe_cryptocontext_t* ctx, int64_t* values, size_t count);
void openfhe_plaintext_destroy(openfhe_plaintext_t* plaintext);

openfhe_ciphertext_t* openfhe_encrypt(openfhe_cryptocontext_t* ctx, openfhe_publickey_t* publicKey, openfhe_plaintext_t* plaintext);
void openfhe_ciphertext_destroy(openfhe_ciphertext_t* ciphertext);

openfhe_plaintext_t* openfhe_decrypt(openfhe_cryptocontext_t* ctx, openfhe_privatekey_t* privateKey, openfhe_ciphertext_t* ciphertext);

// Proxy Re-Encryption
openfhe_reencryptionkey_t* openfhe_rekeygen(openfhe_cryptocontext_t* ctx, openfhe_privatekey_t* oldKey, openfhe_publickey_t* newKey);
void openfhe_reencryptionkey_destroy(openfhe_reencryptionkey_t* reencKey);

openfhe_ciphertext_t* openfhe_reencrypt(openfhe_cryptocontext_t* ctx, openfhe_ciphertext_t* ciphertext, openfhe_reencryptionkey_t* reencKey);

// Utility functions
int openfhe_plaintext_get_packed_value(openfhe_plaintext_t* plaintext, int64_t* values, size_t* count);

#ifdef __cplusplus
}
#endif

#endif // OPENFHE_WRAPPER_H
