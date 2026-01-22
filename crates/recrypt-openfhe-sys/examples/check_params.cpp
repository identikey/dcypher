#include "../src/wrapper.h"
#include <iostream>
#include <chrono>

int main() {
    auto ctx = recrypt_openfhe::create_bfv_context(65537, 60);
    recrypt_openfhe::enable_pke(*ctx);
    recrypt_openfhe::enable_keyswitch(*ctx);
    recrypt_openfhe::enable_leveledshe(*ctx);
    recrypt_openfhe::enable_pre(*ctx);
    
    uint32_t ring_dim = recrypt_openfhe::get_ring_dimension(*ctx);
    std::cout << "Ring dimension: " << ring_dim << std::endl;
    
    // Time key generation
    auto start = std::chrono::high_resolution_clock::now();
    auto kp = recrypt_openfhe::keygen(*ctx);
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "KeyGen took: " << ms << " ms" << std::endl;
    
    // Time recrypt key generation
    auto kp2 = recrypt_openfhe::keygen(*ctx);
    auto pk = recrypt_openfhe::get_public_key(*kp);
    auto sk2 = recrypt_openfhe::get_private_key(*kp2);
    
    start = std::chrono::high_resolution_clock::now();
    auto rk = recrypt_openfhe::generate_recrypt_key(*ctx, *sk2, *pk);
    end = std::chrono::high_resolution_clock::now();
    ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "ReKeyGen took: " << ms << " ms" << std::endl;
    
    // Time encryption of 32 bytes (AES key size)
    std::vector<int64_t> data(16, 42);  // 16 i64 = 32 bytes
    auto pt = recrypt_openfhe::make_packed_plaintext(*ctx, rust::Slice<const int64_t>(data.data(), data.size()));
    
    start = std::chrono::high_resolution_clock::now();
    auto ct = recrypt_openfhe::encrypt(*ctx, *pk, *pt);
    end = std::chrono::high_resolution_clock::now();
    ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "Encrypt (32 bytes) took: " << ms << " ms" << std::endl;
    
    // Time recryption
    start = std::chrono::high_resolution_clock::now();
    auto ct2 = recrypt_openfhe::recrypt(*ctx, *rk, *ct);
    end = std::chrono::high_resolution_clock::now();
    ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "ReEncrypt took: " << ms << " ms" << std::endl;
    
    return 0;
}
