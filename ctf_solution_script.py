#!/usr/bin/env python3
import socket
import string
import time

# TryHackMe W1seGuy CTF Automated Known-Plaintext Attack Solver
HOST = '10.112.178.105'
PORT = 1337

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        time.sleep(1)
        data = s.recv(4096).decode()
        
        # Extract ciphertext
        line = [l for l in data.split('\n') if "This XOR encoded text" in l][0]
        hex_ciphertext = line.split(": ")[1].strip()
        ciphertext_bytes = bytes.fromhex(hex_ciphertext)

        # Brute-force 5-character repeating XOR key via KPA
        known_prefix = b"THM{"
        charset = string.ascii_letters + string.digits
        found_key = ""

        partial_key = bytearray()
        for i in range(4):
            partial_key.append(ciphertext_bytes[i] ^ known_prefix[i])

        base_partial = partial_key.decode('latin1')

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

        print(f"[+] Derived Key: {found_key}")

        # Decrypt Flag 1
        flag1 = "".join([chr(ciphertext_bytes[i] ^ ord(found_key[i % len(found_key)])) for i in range(len(ciphertext_bytes))])
        print(f"[+] Flag 1: {flag1}")

        # Send key for Flag 2
        time.sleep(1)
        s.sendall((found_key + "\n").encode())
        time.sleep(1)
        response = s.recv(4096).decode()
        print(f"[+] Server Response:\n{response}")

    finally:
        s.close()

if __name__ == "__main__":
    solve()