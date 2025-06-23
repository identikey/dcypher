import sys
sys.path.insert(0, 'src')
import subprocess
import hashlib

def test_subprocess_determinism():
    algorithm = 'ML-DSA-87'
    seed = hashlib.sha256(b'test seed').digest()
    
    # Test script that generates a key
    test_script = f"""
import sys
sys.path.insert(0, "src")
from lib.key_manager import KeyManager
import hashlib

seed = {seed!r}
pk, sk = KeyManager.generate_pq_keypair_from_seed("{algorithm}", seed)
print(pk[:10].hex())
"""
    
    # Run the same script twice in separate processes
    result1 = subprocess.run(['uv', 'run', 'python', '-c', test_script], 
                           capture_output=True, text=True, cwd='.')
    result2 = subprocess.run(['uv', 'run', 'python', '-c', test_script], 
                           capture_output=True, text=True, cwd='.')
    
    print(f'First run: {result1.stdout.strip()}')
    print(f'Second run: {result2.stdout.strip()}')
    print(f'Same result: {result1.stdout.strip() == result2.stdout.strip()}')

if __name__ == "__main__":
    test_subprocess_determinism()
