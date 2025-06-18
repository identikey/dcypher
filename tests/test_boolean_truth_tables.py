"""Original C++ code from OpenFHE."""

"""
//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example for the FHEW scheme; it prints out the truth tables for all supported binary gates
 */

#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();

    std::cerr << "Generate cryptocontext" << std::endl;

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other options are TOY, MEDIUM, STD192, and STD256. MEDIUM
    // corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(STD128);

    std::cerr << "Finished generating cryptocontext" << std::endl;

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation."
              << "\n"
              << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1)
    auto ct10 = cc.Encrypt(sk, 1);
    auto ct11 = cc.Encrypt(sk, 1);
    // Encrypt two ciphertexts representing Boolean False (0)
    auto ct00 = cc.Encrypt(sk, 0);
    auto ct01 = cc.Encrypt(sk, 0);

    // Sample Program: Step 4: Evaluation of NAND gates

    auto ctNAND1 = cc.EvalBinGate(NAND, ct10, ct11);
    auto ctNAND2 = cc.EvalBinGate(NAND, ct10, ct01);
    auto ctNAND3 = cc.EvalBinGate(NAND, ct00, ct01);
    auto ctNAND4 = cc.EvalBinGate(NAND, ct00, ct11);

    LWEPlaintext result;

    cc.Decrypt(sk, ctNAND1, &result);
    std::cout << "1 NAND 1 = " << result << std::endl;

    cc.Decrypt(sk, ctNAND2, &result);
    std::cout << "1 NAND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNAND3, &result);
    std::cout << "0 NAND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNAND4, &result);
    std::cout << "0 NAND 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 5: Evaluation of AND gates

    auto ctAND1 = cc.EvalBinGate(AND, ct10, ct11);
    auto ctAND2 = cc.EvalBinGate(AND, ct10, ct01);
    auto ctAND3 = cc.EvalBinGate(AND, ct00, ct01);
    auto ctAND4 = cc.EvalBinGate(AND, ct00, ct11);

    cc.Decrypt(sk, ctAND1, &result);
    std::cout << "1 AND 1 = " << result << std::endl;

    cc.Decrypt(sk, ctAND2, &result);
    std::cout << "1 AND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctAND3, &result);
    std::cout << "0 AND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctAND4, &result);
    std::cout << "0 AND 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 6: Evaluation of OR gates

    auto ctOR1 = cc.EvalBinGate(OR, ct10, ct11);
    auto ctOR2 = cc.EvalBinGate(OR, ct10, ct01);
    auto ctOR3 = cc.EvalBinGate(OR, ct00, ct01);
    auto ctOR4 = cc.EvalBinGate(OR, ct00, ct11);

    cc.Decrypt(sk, ctOR1, &result);
    std::cout << "1 OR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctOR2, &result);
    std::cout << "1 OR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctOR3, &result);
    std::cout << "0 OR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctOR4, &result);
    std::cout << "0 OR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 7: Evaluation of NOR gates

    auto ctNOR1 = cc.EvalBinGate(NOR, ct10, ct11);
    auto ctNOR2 = cc.EvalBinGate(NOR, ct10, ct01);
    auto ctNOR3 = cc.EvalBinGate(NOR, ct00, ct01);
    auto ctNOR4 = cc.EvalBinGate(NOR, ct00, ct11);

    cc.Decrypt(sk, ctNOR1, &result);
    std::cout << "1 NOR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctNOR2, &result);
    std::cout << "1 NOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNOR3, &result);
    std::cout << "0 NOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNOR4, &result);
    std::cout << "0 NOR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 8: Evaluation of XOR gates

    auto ctXOR1 = cc.EvalBinGate(XOR, ct10, ct11);
    auto ctXOR2 = cc.EvalBinGate(XOR, ct10, ct01);
    auto ctXOR3 = cc.EvalBinGate(XOR, ct00, ct01);
    auto ctXOR4 = cc.EvalBinGate(XOR, ct00, ct11);

    cc.Decrypt(sk, ctXOR1, &result);
    std::cout << "1 XOR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctXOR2, &result);
    std::cout << "1 XOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXOR3, &result);
    std::cout << "0 XOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXOR4, &result);
    std::cout << "0 XOR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 9: Evaluation of XNOR gates

    auto ctXNOR1 = cc.EvalBinGate(XNOR, ct10, ct11);
    auto ctXNOR2 = cc.EvalBinGate(XNOR, ct10, ct01);
    auto ctXNOR3 = cc.EvalBinGate(XNOR, ct00, ct01);
    auto ctXNOR4 = cc.EvalBinGate(XNOR, ct00, ct11);

    cc.Decrypt(sk, ctXNOR1, &result);
    std::cout << "1 XNOR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctXNOR2, &result);
    std::cout << "1 XNOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXNOR3, &result);
    std::cout << "0 XNOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXNOR4, &result);
    std::cout << "0 XNOR 1 = " << result << "\n" << std::endl;

    return 0;
}
"""

"""Python code to test the boolean truth tables."""

from openfhe import BINGATE, BINFHE_PARAMSET, BinFHEContext
import pytest


def helper_test_gate(
    gate_name, gate_enum, cc, sk, ct1_a, ct1_b, ct0_a, ct0_b, expected_results
):
    """
    Tests a binary gate with all possible boolean inputs and asserts results.
    """
    print(f"\nEvaluation of {gate_name} gates")

    # Inputs: (1, 1)
    ct_res1 = cc.EvalBinGate(gate_enum, ct1_a, ct1_b)
    res1 = cc.Decrypt(sk, ct_res1)
    print(f"1 {gate_name} 1 = {res1}")
    assert res1 == expected_results[0]

    # Inputs: (1, 0)
    ct_res2 = cc.EvalBinGate(gate_enum, ct1_a, ct0_a)
    res2 = cc.Decrypt(sk, ct_res2)
    print(f"1 {gate_name} 0 = {res2}")
    assert res2 == expected_results[1]

    # Inputs: (0, 1)
    ct_res4 = cc.EvalBinGate(gate_enum, ct0_a, ct1_b)
    res4 = cc.Decrypt(sk, ct_res4)
    print(f"0 {gate_name} 1 = {res4}")
    assert res4 == expected_results[2]

    # Inputs: (0, 0)
    ct_res3 = cc.EvalBinGate(gate_enum, ct0_a, ct0_b)
    res3 = cc.Decrypt(sk, ct_res3)
    print(f"0 {gate_name} 0 = {res3}")
    assert res3 == expected_results[3]


def test_boolean_truth_tables():
    """
    A pytest function to run the truth table tests.
    """
    # Step 1: Set CryptoContext
    cc = BinFHEContext()

    print("Generate cryptocontext")
    cc.GenerateBinFHEContext(BINFHE_PARAMSET.STD128)
    print("Finished generating cryptocontext")

    # Step 2: Key Generation
    sk = cc.KeyGen()
    print("Generating the bootstrapping keys...")
    cc.BTKeyGen(sk)
    print("Completed the key generation.\n")

    # Step 3: Encryption
    ct1_a = cc.Encrypt(sk, 1)
    ct1_b = cc.Encrypt(sk, 1)
    ct0_a = cc.Encrypt(sk, 0)
    ct0_b = cc.Encrypt(sk, 0)

    # Truth table results for (1,1), (1,0), (0,1), (0,0)
    # Step 4: Evaluation of gates
    helper_test_gate(
        "AND", BINGATE.AND, cc, sk, ct1_a, ct1_b, ct0_a, ct0_b, [1, 0, 0, 0]
    )
    helper_test_gate("OR", BINGATE.OR, cc, sk, ct1_a, ct1_b, ct0_a, ct0_b, [1, 1, 1, 0])
    helper_test_gate(
        "NAND", BINGATE.NAND, cc, sk, ct1_a, ct1_b, ct0_a, ct0_b, [0, 1, 1, 1]
    )
    helper_test_gate(
        "NOR", BINGATE.NOR, cc, sk, ct1_a, ct1_b, ct0_a, ct0_b, [0, 0, 0, 1]
    )
    helper_test_gate(
        "XOR", BINGATE.XOR, cc, sk, ct1_a, ct1_b, ct0_a, ct0_b, [0, 1, 1, 0]
    )
    helper_test_gate(
        "XNOR", BINGATE.XNOR, cc, sk, ct1_a, ct1_b, ct0_a, ct0_b, [1, 0, 0, 1]
    )


def test_vhdl_circuit():
    """
    Tests a simple circuit manually synthesized from a VHDL-like description.
    The VHDL code is:
    x <= C nor B;
    y <= A and not(B);
    F <= not(x xor y); -- equivalent to x xnor y
    """
    # Setup FHE
    cc = BinFHEContext()
    cc.GenerateBinFHEContext(BINFHE_PARAMSET.STD128)
    sk = cc.KeyGen()
    cc.BTKeyGen(sk)

    print("\nTesting VHDL circuit F <= (C nor B) xnor (A and not B)")

    # Encrypt a constant 1 for NOT operation
    ct_one = cc.Encrypt(sk, 1)

    # Test all 2^3 = 8 input combinations for A, B, C
    for a_in in [0, 1]:
        for b_in in [0, 1]:
            for c_in in [0, 1]:
                # Plaintext evaluation for expected result
                # x = C nor B
                x = 1 if (c_in == 0 and b_in == 0) else 0
                # not_b = not B
                not_b = 1 - b_in
                # y = A and not_b
                y = a_in & not_b
                # F = x xnor y
                f_expected = 1 if x == y else 0

                # Encrypt inputs
                ct_a = cc.Encrypt(sk, a_in)
                ct_b = cc.Encrypt(sk, b_in)
                ct_c = cc.Encrypt(sk, c_in)

                # FHE execution of the circuit
                # x <= C nor B
                ct_x = cc.EvalBinGate(BINGATE.NOR, ct_c, ct_b)

                # y <= A and not B
                # implement `not B` as `B XOR 1` since input ciphertexts must be independent
                ct_not_b = cc.EvalBinGate(BINGATE.XOR, ct_b, ct_one)
                ct_y = cc.EvalBinGate(BINGATE.AND, ct_a, ct_not_b)

                # F <= x xnor y
                ct_f = cc.EvalBinGate(BINGATE.XNOR, ct_x, ct_y)

                # Decrypt and check
                f_res = cc.Decrypt(sk, ct_f)

                print(
                    f"Inputs A={a_in}, B={b_in}, C={c_in} -> "
                    f"Expected: {f_expected}, Got: {f_res}"
                )
                assert f_res == f_expected


if __name__ == "__main__":
    test_boolean_truth_tables()
    test_vhdl_circuit()
