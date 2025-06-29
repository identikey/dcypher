#!/usr/bin/env python3
"""Simple test for the refactored context manager."""

import threading
import time
from src.crypto.context_manager import CryptoContextManager

def test_singleton_pattern():
    """Test that the singleton pattern works correctly."""
    print("Testing singleton pattern...")
    
    manager1 = CryptoContextManager()
    manager2 = CryptoContextManager()
    
    assert manager1 is manager2, "Singleton pattern failed"
    assert id(manager1) == id(manager2), "Singleton instances have different IDs"
    print("✓ Singleton pattern works correctly")

def test_thread_safety():
    """Test that the singleton is thread-safe."""
    print("Testing thread safety...")
    
    instances = []
    
    def create_instance():
        manager = CryptoContextManager()
        instances.append(manager)
        time.sleep(0.1)  # Simulate some work
    
    # Create multiple threads
    threads = []
    for i in range(10):
        thread = threading.Thread(target=create_instance)
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # All instances should be the same
    first_instance = instances[0]
    for instance in instances:
        assert instance is first_instance, "Thread safety failed - different instances created"
    
    print(f"✓ Thread safety works correctly - all {len(instances)} instances are identical")

def test_context_params():
    """Test context parameter management."""
    print("Testing context parameter management...")
    
    manager = CryptoContextManager()
    
    # Test setting and getting parameters
    test_params = {
        "scheme": "BFV",
        "plaintext_modulus": 65537,
        "multiplicative_depth": 2
    }
    
    manager.set_context_params(test_params)
    retrieved_params = manager.get_context_params()
    
    assert retrieved_params == test_params, "Parameter storage failed"
    
    # Test that we get a copy (defensive programming)
    retrieved_params["new_key"] = "new_value"
    retrieved_params2 = manager.get_context_params()
    assert "new_key" not in retrieved_params2, "Parameters not properly isolated"
    
    print("✓ Context parameter management works correctly")

def test_reset_functionality():
    """Test the reset functionality."""
    print("Testing reset functionality...")
    
    manager = CryptoContextManager()
    
    # Set some parameters
    test_params = {"scheme": "BFV", "plaintext_modulus": 65537}
    manager.set_context_params(test_params)
    
    # Verify they're set
    assert manager.get_context_params() == test_params
    
    # Reset
    manager.reset()
    
    # Verify they're cleared
    assert manager.get_context_params() is None
    assert manager.get_context() is None
    
    print("✓ Reset functionality works correctly")

def test_availability_check():
    """Test the availability check."""
    print("Testing availability check...")
    
    manager = CryptoContextManager()
    availability = manager.is_available()
    
    assert isinstance(availability, bool), "Availability check should return boolean"
    print(f"✓ Availability check works correctly - OpenFHE available: {availability}")

if __name__ == "__main__":
    print("Running simple context manager tests...\n")
    
    try:
        test_singleton_pattern()
        test_thread_safety()
        test_context_params()
        test_reset_functionality()
        test_availability_check()
        
        print("\n🎉 All tests passed! Context manager is thread-safe and working correctly.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()