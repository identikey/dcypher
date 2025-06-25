#!/usr/bin/env python3
"""
Test script to verify liboqs integration
"""

import sys
import os
import ctypes
import pytest


# @pytest.mark.skip(reason="Test disabled temporarily")
def test_liboqs_integration():
    print("=== Testing liboqs Integration ===")
    print(f"Python version: {sys.version}")
    print(f"LD_LIBRARY_PATH: {os.environ.get('LD_LIBRARY_PATH', 'Not set')}")

    # Test if liboqs library can be found
    liboqs_paths = [
        "/app/liboqs-local/lib/liboqs.so",  # Docker path
        "./liboqs-local/lib/liboqs.dylib",  # macOS local path
        "./liboqs-local/lib/liboqs.so",  # Linux local path
    ]

    liboqs_found = False
    for path in liboqs_paths:
        print(f"\nChecking path: {path}")
        if os.path.exists(path):
            print(f" Library file exists: {path}")
            try:
                lib = ctypes.CDLL(path)
                print(f" Successfully loaded liboqs library from {path}")
                print(f"  Library object: {lib}")
                liboqs_found = True
                break
            except Exception as e:
                print(f" Failed to load liboqs from {path}: {e}")
        else:
            print(f"✗ Library file not found: {path}")

    if not liboqs_found:
        print("\n❌ No liboqs library found in any expected location")
        return False

    # Test the KeyManager library finding function
    print("\n=== Testing KeyManager._find_liboqs_library ===")
    try:
        sys.path.insert(0, "/app")  # Add app path for Docker
        from lib.key_manager import KeyManager

        lib = KeyManager._find_liboqs_library()
        if lib:
            print("✓ KeyManager successfully found liboqs library!")
            print(f"  Library: {lib}")

            # Test basic oqs import
            try:
                import oqs

                print("✓ oqs module imported successfully")

                # Test basic key generation
                sig = oqs.Signature("Dilithium2")
                public_key = sig.generate_keypair()
                print(
                    f"✓ Generated Dilithium2 keypair, public key length: {len(public_key)}"
                )

                return True
            except Exception as e:
                print(f"✗ Error testing oqs module: {e}")
                return False
        else:
            print("✗ KeyManager could not find liboqs library")
            return False
    except Exception as e:
        print(f" Error testing KeyManager: {e}")
        import traceback

        traceback.print_exc()
        assert False, f"Error testing KeyManager: {e}"


if __name__ == "__main__":
    test_liboqs_integration()
