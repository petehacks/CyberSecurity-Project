with open('common_passwords.txt') as f:
    common_passwords = f.read().splitlines()
with open('username_hashes.txt') as f:
    text = f.read().splitlines()

# Print each line from username_hashes.txt
for line in text:
    print(line)