# 🧩 TryHackMe — W1seGuy Writeup

<p align="center">
  <img src="https://img.shields.io/badge/Platform-TryHackMe-orange?style=for-the-badge&logo=tryhackme" alt="TryHackMe">
  <img src="https://img.shields.io/badge/Category-Cryptography%20%2F%2F%20Scripting-blue?style=for-the-badge&logo=python" alt="Category">
  <img src="https://img.shields.io/badge/Difficulty-Medium-yellow?style=for-the-badge" alt="Difficulty">
</p>

---

## 📌 Overview
**W1seGuy** is a TryHackMe cryptographic challenge that demonstrates the inherent weaknesses of custom, weak encryption schemes—specifically, **Repeating-Key XOR Encryption** with a short key length. 

This repository contains an automated Python socket script utilizing a **Known-Plaintext Attack (KPA)** to recover the hidden 5-character key and extract both flags.

---

## 🔬 Vulnerability Analysis
1. **Repeating XOR Flaw:** The server encrypts the flag using a static 5-character repeating key. Because the key repeats, bytes at fixed intervals (`i % key_length`) are encrypted with the same key character.
2. **Known-Plaintext Attack (KPA):** We know that all valid flags on TryHackMe begin with the standard prefix `THM{`. 
3. **Key Recovery Logic:** By XORing the first 4 bytes of the ciphertext with `b"THM{"`, we derive the partial key bytes. Testing the possible character variations for the 5th character against the closing brace `}` allows us to pinpoint the exact 5-character key.

---

## 🛠️ The Solution Script (`solve.py`)

The automated script handles network communication, computes the partial key, brute-forces the final character via KPA validation, and retrieves the flags seamlessly.

```python
import socket
import string
import time

HOST = 'YOUR_TARGET_IP'
PORT = 1337

# Connect to the challenge server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

time.sleep(1)
data = s.recv(4096).decode()
print(data)

# Extract Hex Ciphertext
line = [l for l in data.split('\n') if "This XOR encoded text" in l][0]
hex_ciphertext = line.split(": ")[1].strip()
ciphertext_bytes = bytes.fromhex(hex_ciphertext)

# Known Plaintext Attack (KPA)
known_prefix = b"THM{"
charset = string.ascii_letters + string.digits
found_key = ""

partial_key = bytearray()
for i in range(4):
    partial_key.append(ciphertext_bytes[i] ^ known_prefix[i])

base_partial = partial_key.decode('latin1')

# Brute-force the 5th character ensuring valid flag syntax
for c4 in [base_partial[3].lower(), base_partial[3].upper()]:
    test_partial = base_partial[:3] + c4
    for fifth_char in charset:
        test_key = test_partial + fifth_char
        decrypted = ""
        for i in range(len(ciphertext_bytes)):
            decrypted += chr(ciphertext_bytes[i] ^ ord(test_key[i % len(test_key)]))
        
        if decrypted.startswith("THM{") and decrypted.endswith("}"):
            found_key = test_key
            break
    if found_key:
        break

print(f"[+] Found Correct Key: {found_key}")

# Decrypt and display Flag 1
decrypted_flag1 = ""
for i in range(len(ciphertext_bytes)):
    decrypted_flag1 += chr(ciphertext_bytes[i] ^ ord(found_key[i % len(found_key)]))
print(f"True Flag 1: {decrypted_flag1}")

# Send key back to server to retrieve Flag 2
time.sleep(1)
s.sendall((found_key + "\n").encode())
time.sleep(1)
response = s.recv(4096).decode()
print("Server Response:\n", response)

s.close()
