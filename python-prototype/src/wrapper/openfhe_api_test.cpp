#include <iostream>
#include "openfhe.h"

using namespace lbcrypto;

int main() {
    std::cout << "Testing actual OpenFHE API methods..." << std::endl;
    
    try {
        // Create context like Python does
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(65537);
        parameters.SetScalingModSize(60);
        
        auto cc = GenCryptoContext(parameters);
        std::cout << "✓ Context created successfully" << std::endl;
        
        // Enable features
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(PRE);
        std::cout << "✓ Features enabled" << std::endl;
        
        // Test method names - let's see what methods actually exist
        std::cout << "Testing KeyGen..." << std::endl;
        // Try different variations
        try {
            auto kp = cc->KeyGen();
            std::cout << "✓ cc->KeyGen() works" << std::endl;
        } catch (...) {
            std::cout <<"✗ cc->KeyGen() failed" << std::endl;
        }
        
        std::cout << "Testing MakePackedPlaintext..." << std::endl;
        std::vector<int64_t> values = {1, 2, 3, 4};
        try {
            auto pt = cc->MakePackedPlaintext(values);
            std::cout << "✓ cc->MakePackedPlaintext(values) works" << std::endl;
        } catch (...) {
            std::cout << "✗ cc->MakePackedPlaintext(values) failed" << std::endl;
        }
        
        std::cout << "API exploration complete." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception occurred" << std::endl;
        return 1;
    }
    
    return 0;
}
