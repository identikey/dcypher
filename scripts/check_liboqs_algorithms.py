#!/usr/bin/env python3
"""
Check which liboqs algorithms are available.
Useful for debugging MechanismNotEnabledError issues.
"""

try:
    import oqs

    print("✅ liboqs-python imported successfully")

    print("\n📋 Available Signature Mechanisms:")
    sig_mechs = oqs.get_enabled_sig_mechanisms()

    # Filter for ML-DSA algorithms
    ml_dsa_algorithms = [alg for alg in sig_mechs if "ML-DSA" in alg or "ML_DSA" in alg]
    dilithium_algorithms = [alg for alg in sig_mechs if "Dilithium" in alg]

    print(f"📊 Total signature algorithms available: {len(sig_mechs)}")
    print(f"🔒 ML-DSA algorithms: {len(ml_dsa_algorithms)}")
    print(f"🔒 Dilithium algorithms: {len(dilithium_algorithms)}")

    if ml_dsa_algorithms:
        print("\n✅ ML-DSA algorithms found:")
        for alg in sorted(ml_dsa_algorithms):
            print(f"  • {alg}")

    if dilithium_algorithms:
        print("\n✅ Dilithium algorithms found:")
        for alg in sorted(dilithium_algorithms):
            print(f"  • {alg}")

    # Test ML-DSA-87 specifically
    print("\n🧪 Testing ML-DSA-87 availability:")
    try:
        sig = oqs.Signature("ML-DSA-87")
        print("  ✅ ML-DSA-87 is available and working!")
        # No explicit cleanup needed - handled automatically
    except oqs.MechanismNotEnabledError as e:
        print(f"  ❌ ML-DSA-87 not available: {e}")
        print("  💡 Try rebuilding liboqs with: just clean-liboqs && just build-liboqs")
    except Exception as e:
        print(f"  ⚠️  Unexpected error with ML-DSA-87: {e}")

    # Try alternative names
    alternative_names = ["ML_DSA_87", "Dilithium5", "mldsa87"]
    for alt_name in alternative_names:
        try:
            sig = oqs.Signature(alt_name)
            print(f"  ✅ Alternative name '{alt_name}' works!")
            # No explicit cleanup needed - handled automatically
            break
        except:
            continue

    print(f"\n📄 All available signature algorithms:")
    for i, alg in enumerate(sorted(sig_mechs), 1):
        print(f"  {i:2d}. {alg}")

except ImportError as e:
    print(f"❌ Failed to import oqs: {e}")
    print("💡 Make sure liboqs-python is installed: pip install liboqs-python")
except Exception as e:
    print(f"❌ Unexpected error: {e}")
