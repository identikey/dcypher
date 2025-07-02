#include "dcypher_ffi.h"
#include "../wrapper/openfhe_wrapper.h"
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstring>

// Global error state for thread-local error handling
static thread_local std::string g_last_error;

// Helper function to set error and return error code
static dcypher_error_t set_error(dcypher_error_t code, const std::string& message) {
    g_last_error = message;
    return code;
}

// Helper function to allocate and copy string for C interface
static char* allocate_string(const std::string& str) {
    char* result = static_cast<char*>(malloc(str.length() + 1));
    if (result) {
        strcpy(result, str.c_str());
    }
    return result;
}

extern "C" {

// Context management
dcypher_context_t* dcypher_context_create(int plaintext_modulus, int security_level) {
    auto* ctx = openfhe_gen_cryptocontext_bfv(
        plaintext_modulus,
        security_level, 
        3.2f,  // distributionParameter
        2      // maxDepth
    );
    
    if (!ctx) {
        set_error(DCYPHER_ERROR_CONTEXT_CREATION_FAILED, "Failed to create crypto context");
        return nullptr;
    }
    
    // Enable required features
    if (openfhe_cryptocontext_enable_pke(ctx) == 0 ||
        openfhe_cryptocontext_enable_keyswitch(ctx) == 0 ||
        openfhe_cryptocontext_enable_leveledshe(ctx) == 0 ||
        openfhe_cryptocontext_enable_pre(ctx) == 0) {
        openfhe_cryptocontext_destroy(ctx);
        set_error(DCYPHER_ERROR_CONTEXT_CREATION_FAILED, "Failed to enable crypto context features");
        return nullptr;
    }
    
    return reinterpret_cast<dcypher_context_t*>(ctx);
}

void dcypher_context_destroy(dcypher_context_t* ctx) {
    if (ctx) {
        openfhe_cryptocontext_destroy(reinterpret_cast<openfhe_cryptocontext_t*>(ctx));
    }
}

dcypher_error_t dcypher_context_serialize(dcypher_context_t* ctx, char** output, size_t* output_len) {
    if (!ctx || !output || !output_len) {
        return set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in context_serialize");
    }
    
    // TODO: Implement context serialization when needed
    return set_error(DCYPHER_ERROR_SERIALIZATION_FAILED, "Context serialization not yet implemented");
}

dcypher_context_t* dcypher_context_deserialize(const char* data, size_t data_len) {
    if (!data || data_len == 0) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in context_deserialize");
        return nullptr;
    }
    
    // TODO: Implement context deserialization when needed
    set_error(DCYPHER_ERROR_DESERIALIZATION_FAILED, "Context deserialization not yet implemented");
    return nullptr;
}

// Key management
dcypher_keypair_t* dcypher_keygen(dcypher_context_t* ctx) {
    if (!ctx) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null context in keygen");
        return nullptr;
    }
    
    auto* keypair = openfhe_keygen(reinterpret_cast<openfhe_cryptocontext_t*>(ctx));
    if (!keypair) {
        set_error(DCYPHER_ERROR_KEY_GENERATION_FAILED, "Failed to generate key pair");
        return nullptr;
    }
    
    return reinterpret_cast<dcypher_keypair_t*>(keypair);
}

void dcypher_keypair_destroy(dcypher_keypair_t* keypair) {
    if (keypair) {
        openfhe_keypair_destroy(reinterpret_cast<openfhe_keypair_t*>(keypair));
    }
}

dcypher_error_t dcypher_keypair_serialize_public(dcypher_keypair_t* keypair, char** output, size_t* output_len) {
    if (!keypair || !output || !output_len) {
        return set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in keypair_serialize_public");
    }
    
    // TODO: Implement key serialization when needed
    return set_error(DCYPHER_ERROR_SERIALIZATION_FAILED, "Key serialization not yet implemented");
}

dcypher_error_t dcypher_keypair_serialize_private(dcypher_keypair_t* keypair, char** output, size_t* output_len) {
    if (!keypair || !output || !output_len) {
        return set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in keypair_serialize_private");
    }
    
    // TODO: Implement key serialization when needed
    return set_error(DCYPHER_ERROR_SERIALIZATION_FAILED, "Key serialization not yet implemented");
}

dcypher_keypair_t* dcypher_keypair_deserialize(dcypher_context_t* ctx, const char* public_key_data, size_t public_key_len, const char* private_key_data, size_t private_key_len) {
    if (!ctx || !public_key_data || !private_key_data) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in keypair_deserialize");
        return nullptr;
    }
    
    // TODO: Implement key deserialization when needed
    set_error(DCYPHER_ERROR_DESERIALIZATION_FAILED, "Key deserialization not yet implemented");
    return nullptr;
}

// Encryption/Decryption
dcypher_ciphertext_t* dcypher_encrypt(dcypher_context_t* ctx, dcypher_keypair_t* keypair, const int64_t* data, size_t data_len) {
    if (!ctx || !keypair || !data || data_len == 0) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in encrypt");
        return nullptr;
    }
    
    auto* openfhe_ctx = reinterpret_cast<openfhe_cryptocontext_t*>(ctx);
    auto* openfhe_keypair = reinterpret_cast<openfhe_keypair_t*>(keypair);
    
    // Get public key
    auto* public_key = openfhe_keypair_get_publickey(openfhe_keypair);
    if (!public_key) {
        set_error(DCYPHER_ERROR_ENCRYPTION_FAILED, "Failed to get public key");
        return nullptr;
    }
    
    // Create plaintext
    auto* plaintext = openfhe_make_packed_plaintext(openfhe_ctx, const_cast<int64_t*>(data), data_len);
    if (!plaintext) {
        set_error(DCYPHER_ERROR_ENCRYPTION_FAILED, "Failed to create plaintext");
        return nullptr;
    }
    
    // Encrypt
    auto* ciphertext = openfhe_encrypt(openfhe_ctx, public_key, plaintext);
    openfhe_plaintext_destroy(plaintext);
    
    if (!ciphertext) {
        set_error(DCYPHER_ERROR_ENCRYPTION_FAILED, "Failed to encrypt data");
        return nullptr;
    }
    
    return reinterpret_cast<dcypher_ciphertext_t*>(ciphertext);
}

dcypher_error_t dcypher_decrypt(dcypher_context_t* ctx, dcypher_keypair_t* keypair, dcypher_ciphertext_t* ciphertext, int64_t** output, size_t* output_len) {
    if (!ctx || !keypair || !ciphertext || !output || !output_len) {
        return set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in decrypt");
    }
    
    auto* openfhe_ctx = reinterpret_cast<openfhe_cryptocontext_t*>(ctx);
    auto* openfhe_keypair = reinterpret_cast<openfhe_keypair_t*>(keypair);
    auto* openfhe_ciphertext = reinterpret_cast<openfhe_ciphertext_t*>(ciphertext);
    
    // Get private key
    auto* private_key = openfhe_keypair_get_privatekey(openfhe_keypair);
    if (!private_key) {
        return set_error(DCYPHER_ERROR_DECRYPTION_FAILED, "Failed to get private key");
    }
    
    // Decrypt
    auto* decrypted = openfhe_decrypt(openfhe_ctx, private_key, openfhe_ciphertext);
    if (!decrypted) {
        return set_error(DCYPHER_ERROR_DECRYPTION_FAILED, "Failed to decrypt data");
    }
    
    // Extract values
    const size_t max_values = 1024; // Reasonable limit
    int64_t* values = static_cast<int64_t*>(malloc(max_values * sizeof(int64_t)));
    if (!values) {
        openfhe_plaintext_destroy(decrypted);
        return set_error(DCYPHER_ERROR_MEMORY_ALLOCATION_FAILED, "Failed to allocate output buffer");
    }
    
    size_t actual_count = max_values;
    if (openfhe_plaintext_get_packed_value(decrypted, values, &actual_count) == 0) {
        free(values);
        openfhe_plaintext_destroy(decrypted);
        return set_error(DCYPHER_ERROR_DECRYPTION_FAILED, "Failed to extract decrypted values");
    }
    
    openfhe_plaintext_destroy(decrypted);
    
    // Resize buffer to actual size
    int64_t* final_values = static_cast<int64_t*>(realloc(values, actual_count * sizeof(int64_t)));
    if (!final_values && actual_count > 0) {
        free(values);
        return set_error(DCYPHER_ERROR_MEMORY_ALLOCATION_FAILED, "Failed to resize output buffer");
    }
    
    *output = final_values;
    *output_len = actual_count;
    return DCYPHER_SUCCESS;
}

void dcypher_ciphertext_destroy(dcypher_ciphertext_t* ciphertext) {
    if (ciphertext) {
        openfhe_ciphertext_destroy(reinterpret_cast<openfhe_ciphertext_t*>(ciphertext));
    }
}

dcypher_error_t dcypher_ciphertext_serialize(dcypher_ciphertext_t* ciphertext, char** output, size_t* output_len) {
    if (!ciphertext || !output || !output_len) {
        return set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in ciphertext_serialize");
    }
    
    // TODO: Implement ciphertext serialization when needed
    return set_error(DCYPHER_ERROR_SERIALIZATION_FAILED, "Ciphertext serialization not yet implemented");
}

dcypher_ciphertext_t* dcypher_ciphertext_deserialize(dcypher_context_t* ctx, const char* data, size_t data_len) {
    if (!ctx || !data || data_len == 0) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in ciphertext_deserialize");
        return nullptr;
    }
    
    // TODO: Implement ciphertext deserialization when needed
    set_error(DCYPHER_ERROR_DESERIALIZATION_FAILED, "Ciphertext deserialization not yet implemented");
    return nullptr;
}

// Proxy Re-encryption
dcypher_reenc_key_t* dcypher_rekey_gen(dcypher_context_t* ctx, dcypher_keypair_t* from_key, dcypher_keypair_t* to_key) {
    if (!ctx || !from_key || !to_key) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in rekey_gen");
        return nullptr;
    }
    
    auto* openfhe_ctx = reinterpret_cast<openfhe_cryptocontext_t*>(ctx);
    auto* openfhe_from_key = reinterpret_cast<openfhe_keypair_t*>(from_key);
    auto* openfhe_to_key = reinterpret_cast<openfhe_keypair_t*>(to_key);
    
    // Get keys
    auto* from_private = openfhe_keypair_get_privatekey(openfhe_from_key);
    auto* to_public = openfhe_keypair_get_publickey(openfhe_to_key);
    
    if (!from_private || !to_public) {
        set_error(DCYPHER_ERROR_REENCRYPTION_FAILED, "Failed to get keys for re-encryption key generation");
        return nullptr;
    }
    
    auto* reenc_key = openfhe_rekeygen(openfhe_ctx, from_private, to_public);
    if (!reenc_key) {
        set_error(DCYPHER_ERROR_REENCRYPTION_FAILED, "Failed to generate re-encryption key");
        return nullptr;
    }
    
    return reinterpret_cast<dcypher_reenc_key_t*>(reenc_key);
}

void dcypher_reenc_key_destroy(dcypher_reenc_key_t* reenc_key) {
    if (reenc_key) {
        openfhe_reencryptionkey_destroy(reinterpret_cast<openfhe_reencryptionkey_t*>(reenc_key));
    }
}

dcypher_ciphertext_t* dcypher_reencrypt(dcypher_context_t* ctx, dcypher_ciphertext_t* ciphertext, dcypher_reenc_key_t* reenc_key) {
    if (!ctx || !ciphertext || !reenc_key) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in reencrypt");
        return nullptr;
    }
    
    auto* openfhe_ctx = reinterpret_cast<openfhe_cryptocontext_t*>(ctx);
    auto* openfhe_ciphertext = reinterpret_cast<openfhe_ciphertext_t*>(ciphertext);
    auto* openfhe_reenc_key = reinterpret_cast<openfhe_reencryptionkey_t*>(reenc_key);
    
    auto* reencrypted = openfhe_reencrypt(openfhe_ctx, openfhe_ciphertext, openfhe_reenc_key);
    if (!reencrypted) {
        set_error(DCYPHER_ERROR_REENCRYPTION_FAILED, "Failed to re-encrypt ciphertext");
        return nullptr;
    }
    
    return reinterpret_cast<dcypher_ciphertext_t*>(reencrypted);
}

dcypher_error_t dcypher_reenc_key_serialize(dcypher_reenc_key_t* reenc_key, char** output, size_t* output_len) {
    if (!reenc_key || !output || !output_len) {
        return set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in reenc_key_serialize");
    }
    
    // TODO: Implement re-encryption key serialization when needed
    return set_error(DCYPHER_ERROR_SERIALIZATION_FAILED, "Re-encryption key serialization not yet implemented");
}

dcypher_reenc_key_t* dcypher_reenc_key_deserialize(dcypher_context_t* ctx, const char* data, size_t data_len) {
    if (!ctx || !data || data_len == 0) {
        set_error(DCYPHER_ERROR_NULL_POINTER, "Null pointer in reenc_key_deserialize");
        return nullptr;
    }
    
    // TODO: Implement re-encryption key deserialization when needed
    set_error(DCYPHER_ERROR_DESERIALIZATION_FAILED, "Re-encryption key deserialization not yet implemented");
    return nullptr;
}

// Error handling
const char* dcypher_get_last_error(void) {
    return g_last_error.empty() ? nullptr : g_last_error.c_str();
}

void dcypher_clear_error(void) {
    g_last_error.clear();
}

// Memory management
void dcypher_free_string(char* str) {
    if (str) {
        free(str);
    }
}

} // extern "C"