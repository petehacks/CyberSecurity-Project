import hashlib


password = "python_is_fun"
hash = hashlib.sha256 (password.encode('utf-8'))
print(hash.hexdigest())
