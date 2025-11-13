import hashlib

def load_file_lines(filepath):
    """
    Reads a text file and returns a list of stripped lines.
    
    Args:
        filepath (str): Path to the text file.
        
    Returns:
        list[str]: List of lines from the file.
    """
    with open(filepath, 'r') as file:
        return [line.strip() for line in file]

def build_user_hash_map(filename):
    """
    Reads a file containing username:hash pairs and builds a dictionary.
    
    Args:
        filename (str): Path to the username-hash file.
        
    Returns:
        dict[str, str]: Dictionary mapping usernames to their hashes.
    """
    user_hash_map = {}
    lines = load_file_lines(filename)
    for line in lines:
        try:
            username, password_hash = line.split(':', 1)
            user_hash_map[username] = password_hash
        except ValueError:
            print(f"Skipping malformed line: {line}")
    return user_hash_map

def hash_common_passwords(passwords):
    """
    Hashes a list of plaintext passwords using SHA-256 and returns a dictionary.
    
    Args:
        passwords (list[str]): List of plaintext passwords.
        
    Returns:
        dict[str, str]: Dictionary mapping hashed password -> plaintext password.
    """
    hashed_dict = {}
    for password in passwords:
        hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
        hashed_dict[hashed] = password
    return hashed_dict

def crack_passwords(user_hash_map, hashed_password_map):
    """
    Attempts to find plaintext passwords for given username hashes using pre-hashed common passwords.
    
    Args:
        user_hash_map (dict[str, str]): Map of usernames to hashed passwords.
        hashed_password_map (dict[str, str]): Map of hashed password -> plaintext password.
    """
    for username, stored_hash in user_hash_map.items():
        if stored_hash in hashed_password_map:
            print(f'HASH FOUND: {username}:{hashed_password_map[stored_hash]}')

def main():
    """Main function to run the password cracking process."""
    common_passwords = load_file_lines('common_passwords.txt')
    user_hash_map = build_user_hash_map('username_hashes.txt')
    
    hashed_password_map = hash_common_passwords(common_passwords)
    crack_passwords(user_hash_map, hashed_password_map)

if __name__ == "__main__":
    main()
