#!/usr/bin/env python3
"""
Scapy Import Test - Debug script to check scapy availability
"""
import sys
import os

print("Python Scapy Import Diagnostic")
print("=" * 40)
print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print(f"Running as root: {os.geteuid() == 0}")
print()

print("Python paths:")
for i, path in enumerate(sys.path):
    print(f"  {i}: {path}")
print()

# Try basic import
print("Testing basic import...")
try:
    import scapy
    print("✓ Basic import successful")
    print(f"  Scapy location: {scapy.__file__}")
    print(f"  Scapy version: {scapy.__version__ if hasattr(scapy, '__version__') else 'unknown'}")
except ImportError as e:
    print(f"✗ Basic import failed: {e}")

# Try with site packages
print("\nTesting with site packages...")
try:
    import site
    sys.path.extend(site.getsitepackages())
    import scapy
    print("✓ Import with site packages successful")
except ImportError as e:
    print(f"✗ Import with site packages failed: {e}")

# Try with explicit path
print("\nTesting with explicit paths...")
explicit_paths = [
    '/usr/local/lib/python3.10/dist-packages',
    '/usr/lib/python3/dist-packages',
    '/usr/local/lib/python3.11/dist-packages',
    '/usr/local/lib/python3.9/dist-packages'
]

for path in explicit_paths:
    if os.path.exists(path):
        print(f"  Found path: {path}")
        if os.path.exists(os.path.join(path, 'scapy')):
            print(f"    ✓ Scapy found in {path}")
            try:
                if path not in sys.path:
                    sys.path.insert(0, path)
                import scapy
                print(f"    ✓ Import successful from {path}")
                break
            except ImportError:
                print(f"    ✗ Import failed from {path}")
        else:
            print(f"    - No scapy in {path}")
    else:
        print(f"  Path does not exist: {path}")

print("\nChecking pip installation...")
import subprocess
try:
    result = subprocess.run(['pip3', 'show', 'scapy'], capture_output=True, text=True)
    if result.returncode == 0:
        print("✓ Pip shows scapy is installed")
        for line in result.stdout.split('\n'):
            if line.startswith('Location:'):
                print(f"  {line}")
    else:
        print("✗ Pip does not show scapy as installed")
except Exception as e:
    print(f"✗ Error checking pip: {e}")