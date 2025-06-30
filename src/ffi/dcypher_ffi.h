#ifndef DCYPHER_FFI_H
#define DCYPHER_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
typedef enum {
    DCYPHER_SUCCESS = 0,
    DCYPHER_ERROR_NULL_POINTER = -1,
    DCYPHER_ERROR_INVALID_PARAMETER = -2,
    DCYPHER_ERROR_CONTEXT_CREATION_FAILED = -3,
    DCYPHER_ERROR_KEY_GENERATION_FAILED = -4,
    DCYPHER_ERROR_ENCRYPTION_FAILED = -5,
    DCYPHER_ERROR_DECRYPTION_FAILED = -6,
    DCYPHER_ERROR_REENCRYPTION_FAILED = -7,
    DCYPHER_ERROR_SERIALIZATION_FAILED = -8,
    DCYPHER_ERROR_DESERIALIZATION_FAILED = -9,
    DCYPHER_ERROR_MEMORY_ALLOCATION_FAILED = -10,
    DCYPHER_ERROR_UNKNOWN = -999
} dcypher_error_t;

// Opaque types for C interface
typedef struct dcypher_context dcypher_context_t;
typedef struct dcypher_keypair dcypher_keypair_t;
typedef struct dcypher_ciphertext dcypher_ciphertext_t;
typedef struct dcypher_reenc_key dcypher_reenc_key_t;

// Context management
dcypher_context_t* dcypher_context_create(int plaintext_modulus, int security_level);
void dcypher_context_destroy(dcypher_context_t* ctx);
dcypher_error_t dcypher_context_serialize(dcypher_context_t* ctx, char** output, size_t* output_len);
dcypher_context_t* dcypher_context_deserialize(const char* data, size_t data_len);

// Key management
dcypher_keypair_t* dcypher_keygen(dcypher_context_t* ctx);
void dcypher_keypair_destroy(dcypher_keypair_t* keypair);
dcypher_error_t dcypher_keypair_serialize_public(dcypher_keypair_t* keypair, char** output, size_t* output_len);
dcypher_error_t dcypher_keypair_serialize_private(dcypher_keypair_t* keypair, char** output, size_t* output_len);
dcypher_keypair_t* dcypher_keypair_deserialize(dcypher_context_t* ctx, const char* public_key_data, size_t public_key_len, const char* private_key_data, size_t private_key_len);

// Encryption/Decryption
dcypher_ciphertext_t* dcypher_encrypt(dcypher_context_t* ctx, dcypher_keypair_t* keypair, const int64_t* data, size_t data_len);
dcypher_error_t dcypher_decrypt(dcypher_context_t* ctx, dcypher_keypair_t* keypair, dcypher_ciphertext_t* ciphertext, int64_t** output, size_t* output_len);
void dcypher_ciphertext_destroy(dcypher_ciphertext_t* ciphertext);
dcypher_error_t dcypher_ciphertext_serialize(dcypher_ciphertext_t* ciphertext, char** output, size_t* output_len);
dcypher_ciphertext_t* dcypher_ciphertext_deserialize(dcypher_context_t* ctx, const char* data, size_t data_len);

// Proxy Re-encryption
dcypher_reenc_key_t* dcypher_rekey_gen(dcypher_context_t* ctx, dcypher_keypair_t* from_key, dcypher_keypair_t* to_key);
void dcypher_reenc_key_destroy(dcypher_reenc_key_t* reenc_key);
dcypher_ciphertext_t* dcypher_reencrypt(dcypher_context_t* ctx, dcypher_ciphertext_t* ciphertext, dcypher_reenc_key_t* reenc_key);
dcypher_error_t dcypher_reenc_key_serialize(dcypher_reenc_key_t* reenc_key, char** output, size_t* output_len);
dcypher_reenc_key_t* dcypher_reenc_key_deserialize(dcypher_context_t* ctx, const char* data, size_t data_len);

// Error handling
const char* dcypher_get_last_error(void);
void dcypher_clear_error(void);

// Memory management
void dcypher_free_string(char* str);

#ifdef __cplusplus
}
#endif

#endif // DCYPHER_FFI_H