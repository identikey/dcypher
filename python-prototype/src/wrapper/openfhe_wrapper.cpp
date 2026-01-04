#include "openfhe_wrapper.h"

// Include OpenFHE headers
#include "openfhe.h"

using namespace lbcrypto;

// TODO: Fix OpenFHE API usage to match actual headers - currently stubbed for unified FFI testing
// This allows testing the unified C FFI API architecture with static linking

// Wrapper implementations
extern "C" {

openfhe_cryptocontext_t* openfhe_gen_cryptocontext_bfv(
    int plaintextModulus,
    int securityLevel,
    float distributionParameter,
    int maxDepth
) {
    // Suppress unused parameter warnings
    (void)securityLevel; (void)distributionParameter; (void)maxDepth;
    try {
        // Use CCParamsBFVRNS as shown in Python implementation
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(plaintextModulus);
        parameters.SetScalingModSize(60); // Default from Python
        
        // Generate crypto context (returns shared_ptr)
        auto context = GenCryptoContext(parameters);
        
        // Enable required features
        context->Enable(PKE);
        context->Enable(KEYSWITCH);
        context->Enable(LEVELEDSHE);
        context->Enable(PRE);
        
        // Store the shared_ptr directly
        auto* ctx_ptr = new CryptoContext<DCRTPoly>(context);
        return reinterpret_cast<openfhe_cryptocontext_t*>(ctx_ptr);
    } catch (...) {
        return nullptr;
    }
}

void openfhe_cryptocontext_destroy(openfhe_cryptocontext_t* ctx) {
    if (ctx) {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        delete context;
    }
}

int openfhe_cryptocontext_enable_pke(openfhe_cryptocontext_t* ctx) {
    // TODO: Implement with correct OpenFHE API
    (void)ctx;
    return 1; // Dummy success
}

int openfhe_cryptocontext_enable_keyswitch(openfhe_cryptocontext_t* ctx) {
    // TODO: Implement with correct OpenFHE API
    (void)ctx;
    return 1; // Dummy success
}

int openfhe_cryptocontext_enable_leveledshe(openfhe_cryptocontext_t* ctx) {
    // TODO: Implement with correct OpenFHE API
    (void)ctx;
    return 1; // Dummy success
}

int openfhe_cryptocontext_enable_pre(openfhe_cryptocontext_t* ctx) {
    // TODO: Implement with correct OpenFHE API
    (void)ctx;
    return 1; // Dummy success
}

openfhe_keypair_t* openfhe_keygen(openfhe_cryptocontext_t* ctx) {
    if (!ctx) return nullptr;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        auto keypair = (*context)->KeyGen();
        auto* kp = new KeyPair<DCRTPoly>(keypair);
        return reinterpret_cast<openfhe_keypair_t*>(kp);
    } catch (...) {
        return nullptr;
    }
}

void openfhe_keypair_destroy(openfhe_keypair_t* keypair) {
    if (keypair) {
        auto* kp = reinterpret_cast<KeyPair<DCRTPoly>*>(keypair);
        delete kp;
    }
}

openfhe_publickey_t* openfhe_keypair_get_publickey(openfhe_keypair_t* keypair) {
    if (!keypair) return nullptr;
    auto* kp = reinterpret_cast<KeyPair<DCRTPoly>*>(keypair);
    return reinterpret_cast<openfhe_publickey_t*>(&kp->publicKey);
}

openfhe_privatekey_t* openfhe_keypair_get_privatekey(openfhe_keypair_t* keypair) {
    if (!keypair) return nullptr;
    auto* kp = reinterpret_cast<KeyPair<DCRTPoly>*>(keypair);
    return reinterpret_cast<openfhe_privatekey_t*>(&kp->secretKey);
}

openfhe_plaintext_t* openfhe_make_packed_plaintext(openfhe_cryptocontext_t* ctx, int64_t* values, size_t count) {
    if (!ctx || !values) return nullptr;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        std::vector<int64_t> vec(values, values + count);
        auto plaintext = (*context)->MakePackedPlaintext(vec);
        auto* pt = new Plaintext(plaintext);
        return reinterpret_cast<openfhe_plaintext_t*>(pt);
    } catch (...) {
        return nullptr;
    }
}

void openfhe_plaintext_destroy(openfhe_plaintext_t* plaintext) {
    if (plaintext) {
        auto* pt = reinterpret_cast<Plaintext*>(plaintext);
        delete pt;
    }
}

openfhe_ciphertext_t* openfhe_encrypt(openfhe_cryptocontext_t* ctx, openfhe_publickey_t* publicKey, openfhe_plaintext_t* plaintext) {
    if (!ctx || !publicKey || !plaintext) return nullptr;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        auto* pubKey = reinterpret_cast<PublicKey<DCRTPoly>*>(publicKey);
        auto* pt = reinterpret_cast<Plaintext*>(plaintext);
        auto ciphertext = (*context)->Encrypt(*pubKey, *pt);
        auto* ct = new Ciphertext<DCRTPoly>(ciphertext);
        return reinterpret_cast<openfhe_ciphertext_t*>(ct);
    } catch (...) {
        return nullptr;
    }
}

void openfhe_ciphertext_destroy(openfhe_ciphertext_t* ciphertext) {
    if (ciphertext) {
        auto* ct = reinterpret_cast<Ciphertext<DCRTPoly>*>(ciphertext);
        delete ct;
    }
}

openfhe_plaintext_t* openfhe_decrypt(openfhe_cryptocontext_t* ctx, openfhe_privatekey_t* privateKey, openfhe_ciphertext_t* ciphertext) {
    if (!ctx || !privateKey || !ciphertext) return nullptr;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        auto* privKey = reinterpret_cast<PrivateKey<DCRTPoly>*>(privateKey);
        auto* ct = reinterpret_cast<Ciphertext<DCRTPoly>*>(ciphertext);
        Plaintext result;
        (*context)->Decrypt(*privKey, *ct, &result);
        auto* plaintext = new Plaintext(result);
        return reinterpret_cast<openfhe_plaintext_t*>(plaintext);
    } catch (...) {
        return nullptr;
    }
}

openfhe_reencryptionkey_t* openfhe_rekeygen(openfhe_cryptocontext_t* ctx, openfhe_privatekey_t* oldKey, openfhe_publickey_t* newKey) {
    if (!ctx || !oldKey || !newKey) return nullptr;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        auto* oldPrivKey = reinterpret_cast<PrivateKey<DCRTPoly>*>(oldKey);
        auto* newPubKey = reinterpret_cast<PublicKey<DCRTPoly>*>(newKey);
        auto reencKey = (*context)->ReKeyGen(*oldPrivKey, *newPubKey);
        auto* rk = new EvalKey<DCRTPoly>(reencKey);
        return reinterpret_cast<openfhe_reencryptionkey_t*>(rk);
    } catch (...) {
        return nullptr;
    }
}

void openfhe_reencryptionkey_destroy(openfhe_reencryptionkey_t* reencKey) {
    if (reencKey) {
        auto* rk = reinterpret_cast<EvalKey<DCRTPoly>*>(reencKey);
        delete rk;
    }
}

openfhe_ciphertext_t* openfhe_reencrypt(openfhe_cryptocontext_t* ctx, openfhe_ciphertext_t* ciphertext, openfhe_reencryptionkey_t* reencKey) {
    if (!ctx || !ciphertext || !reencKey) return nullptr;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        auto* ct = reinterpret_cast<Ciphertext<DCRTPoly>*>(ciphertext);
        auto* rk = reinterpret_cast<EvalKey<DCRTPoly>*>(reencKey);
        auto result = (*context)->ReEncrypt(*ct, *rk);
        auto* new_ct = new Ciphertext<DCRTPoly>(result);
        return reinterpret_cast<openfhe_ciphertext_t*>(new_ct);
    } catch (...) {
        return nullptr;
    }
}

int openfhe_plaintext_get_packed_value(openfhe_plaintext_t* plaintext, int64_t* values, size_t* count) {
    if (!plaintext || !values || !count) return 0;
    try {
        auto* pt = reinterpret_cast<Plaintext*>(plaintext);
        auto vec = (*pt)->GetPackedValue();
        
        size_t copyCount = std::min(*count, vec.size());
        for (size_t i = 0; i < copyCount; i++) {
            values[i] = vec[i];
        }
        *count = vec.size();
        return 1;
    } catch (...) {
        return 0;
    }
}

} // extern "C"
