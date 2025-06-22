#include "openfhe_wrapper.h"

// Include OpenFHE headers
#include "openfhe.h"

using namespace lbcrypto;

// Wrapper implementations
extern "C" {

openfhe_cryptocontext_t* openfhe_gen_cryptocontext_bfv(
    int plaintextModulus,
    int securityLevel,
    float distributionParameter,
    int maxDepth
) {
    try {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(plaintextModulus);
        parameters.SetSecurityLevel(static_cast<SecurityLevel>(securityLevel));
        parameters.SetDistributionParameter(distributionParameter);
        parameters.SetMaxDepth(maxDepth);

        auto* context = new CryptoContext<DCRTPoly>(GenCryptoContext(parameters));
        return reinterpret_cast<openfhe_cryptocontext_t*>(context);
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
    if (!ctx) return 0;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        context->Enable(PKE);
        return 1;
    } catch (...) {
        return 0;
    }
}

int openfhe_cryptocontext_enable_keyswitch(openfhe_cryptocontext_t* ctx) {
    if (!ctx) return 0;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        context->Enable(KEYSWITCH);
        return 1;
    } catch (...) {
        return 0;
    }
}

int openfhe_cryptocontext_enable_leveledshe(openfhe_cryptocontext_t* ctx) {
    if (!ctx) return 0;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        context->Enable(LEVELEDSHE);
        return 1;
    } catch (...) {
        return 0;
    }
}

int openfhe_cryptocontext_enable_pre(openfhe_cryptocontext_t* ctx) {
    if (!ctx) return 0;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        context->Enable(PRE);
        return 1;
    } catch (...) {
        return 0;
    }
}

openfhe_keypair_t* openfhe_keygen(openfhe_cryptocontext_t* ctx) {
    if (!ctx) return nullptr;
    try {
        auto* context = reinterpret_cast<CryptoContext<DCRTPoly>*>(ctx);
        auto* keypair = new KeyPair<DCRTPoly>(context->KeyGen());
        return reinterpret_cast<openfhe_keypair_t*>(keypair);
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
        auto* plaintext = new Plaintext(context->MakePackedPlaintext(vec));
        return reinterpret_cast<openfhe_plaintext_t*>(plaintext);
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
        auto* ciphertext = new Ciphertext<DCRTPoly>(context->Encrypt(*pubKey, *pt));
        return reinterpret_cast<openfhe_ciphertext_t*>(ciphertext);
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
        context->Decrypt(*privKey, *ct, &result);
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
        auto* reencKey = new EvalKey<DCRTPoly>(context->ReKeyGen(*oldPrivKey, *newPubKey));
        return reinterpret_cast<openfhe_reencryptionkey_t*>(reencKey);
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
        auto* result = new Ciphertext<DCRTPoly>(context->ReEncrypt(*ct, *rk));
        return reinterpret_cast<openfhe_ciphertext_t*>(result);
    } catch (...) {
        return nullptr;
    }
}

int openfhe_plaintext_get_packed_value(openfhe_plaintext_t* plaintext, int64_t* values, size_t* count) {
    if (!plaintext || !values || !count) return 0;
    try {
        auto* pt = reinterpret_cast<Plaintext*>(plaintext);
        auto vec = pt->GetPackedValue();
        
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
