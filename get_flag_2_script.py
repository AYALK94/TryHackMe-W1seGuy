import socket
import string
import time

HOST = '10.112.178.105'
PORT = 1337

# Connect to the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

time.sleep(1)
data = s.recv(4096).decode()
print("--- Server Banner ---")
print(data)

# Extract the hex ciphertext
line = [l for l in data.split('\n') if "This XOR encoded text" in l][0]
hex_ciphertext = line.split(": ")[1].strip()
ciphertext_bytes = bytes.fromhex(hex_ciphertext)

# Known Plaintext Attack to find the key
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

print(f"\n[+] Found Correct Key: {found_key}")

# Calculate and show True Flag 1
decrypted_flag1 = ""
for i in range(len(ciphertext_bytes)):
    decrypted_flag1 += chr(ciphertext_bytes[i] ^ ord(found_key[i % len(found_key)]))
print(f"True Flag 1: {decrypted_flag1}")

# Send key back to server to retrieve Flag 2
time.sleep(1)
s.sendall((found_key + "\n").encode())

time.sleep(1)
response = s.recv(4096).decode()
print("\n--- Server Response (Flag 2) ---")
print(response)

s.close()