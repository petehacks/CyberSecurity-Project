from cryptography.hazmat.primitives import padding 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii, base64

# Inputs
key_hex = "5468617473206D79204B756E67204675"
iv_text = "1234567890abcdef"
cipher_b64 = "q1GqY0zbd3V0lXj7xKZbHg=="

# convert inputs
key = binascii.unhexlify(key_hex)       # bytes: b'Thats my Kung Fu'
iv = iv_text.encode('utf-8')            # bytes: b'1234567890abcdef'
ciphertext = base64.b64decode(cipher_b64)

# Decrypt
backend = default_backend()
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
decryptor = cipher.decryptor()
padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

# Remove PKCS#7 padding
pad_len = padded_plain[-1]
if not 1 <= pad_len <= 16:
    raise ValueError("Invalid padding length")
plaintext = padded_plain[:-pad_len]

print("Plaintext:", plaintext.decode('utf-8'))