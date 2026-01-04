#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;

int main() {
    std::cout << "Exploring OpenFHE API for static linking..." << std::endl;
    
    // Just test that we can include the header and compile
    std::cout << "✓ OpenFHE headers included successfully" << std::endl;
    
    // Test what classes are available
    std::cout << "Testing available classes and methods..." << std::endl;
    
    // Since we know this works from Python: fhe.CCParamsBFVRNS()
    // Let's see what's actually available in C++
    
    return 0;
}
