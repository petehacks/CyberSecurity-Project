import hashlib


password = "welcome123"
hash = hashlib.sha256 (password.encode('utf-8'))
print(hash.hexdigest())
