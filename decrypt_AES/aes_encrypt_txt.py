from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

def aes_encrypt(plaintext, key, iv):
    """
    Encrypt plaintext using AES CBC mode and return Base64 ciphertext.
    """
    key_bytes = key.encode()
    iv_bytes = iv.encode()

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return base64.b64encode(ciphertext).decode('utf-8')


# ---------------- USER INPUT SECTION ----------------

# 🔑 Use the same key you will use for decryption (must be 16, 24, or 32 chars)
secret_key = "A1B2C3D4E5F6G7H8"

# 🔐 IV must be exactly 16 chars
iv = "1a2b3c4d5e6f7g8h"

# ✏️ Text you want to encrypt for testing
plaintext = "second test message"

# ----------------------------------------------------

encrypted_text = aes_encrypt(plaintext, secret_key, iv)
print("Encrypted Base64 ciphertext:\n", encrypted_text)
