#!/usr/bin/env python3
"""Test script to generate CPU load and test process monitoring"""

import time
import threading
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def cpu_load_worker():
    """Worker function to generate CPU load"""
    end_time = time.time() + 3  # Run for 3 seconds
    while time.time() < end_time:
        # Simple CPU-intensive calculation
        sum(x*x for x in range(10000))

def test_with_load():
    """Test process monitoring with CPU load"""
    print("Starting CPU load test...")
    
    # Start a few threads to generate load
    threads = []
    for i in range(3):
        t = threading.Thread(target=cpu_load_worker)
        t.start()
        threads.append(t)
    
    # Wait for threads to complete
    for t in threads:
        t.join()
        
    print("CPU load test completed!")

if __name__ == "__main__":
    test_with_load()
