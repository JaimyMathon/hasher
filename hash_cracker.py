import argparse
import hashlib
import sys

# Function for converting text to sha-1 
def convert_text_to_sha1(text):
    digest = hashlib.sha1(text.encode()).hexdigest()
    return digest

# Function for converting text to md5
def convert_text_to_md5(text):
    digest = hashlib.md5(text.encode()).hexdigest()
    return digest

# Function for converting text to md2 
def convert_text_to_sha224(text):
    digest = hashlib.sha224(text.encode()).hexdigest()
    return digest

# Function for looking for password with sha-1 hash
def sha1(decrypt_hash):
    clean_sha1 = decrypt_hash.strip().lower()

    with open('./passwords.txt') as f:
        for line in f:
            password = line.strip()
            converted_sha1 = convert_text_to_sha1(password)
            if clean_sha1 == converted_sha1:
                print(f"Password found: {password}")
                return

    print("Could not find the password") 

# Function for looking for password with md5 hash
def md5(decrypt_hash):
    clean_md5 = decrypt_hash.strip().lower()

    with open("./passwords.txt") as f:
        for line in f:
            password = line.strip()
            converted_md5 = convert_text_to_md5(password)
            if clean_md5 == converted_md5:
                print(f"Password found: {password}")
                return
    print("could not find the password")

# Function for looking for password with sha224 hash
def sha224(decrypt_hash):
    clean_sha224 = decrypt_hash.strip().lower()

    with open("./passwords.txt") as f:
        for line in f:
            password = line.strip()
            converted_sha224 = convert_text_to_sha224(password)
            if clean_sha224 == converted_sha224:
                print(f"Password found: {password}")
                return
    print("could not find the password")

# Function for hashing plain text
def hash_text(text, hash_type):
    if hash_type == "sha1":
        return convert_text_to_sha1(text)
    elif hash_type == "md5":
        return convert_text_to_md5(text)
    elif hash_type == "sha224":
        return convert_text_to_sha224(text)
    else:
        return "Invalid hash type. Please choose 'sha1', 'md5', 'sha224'."

# Main program
def main():
    parser = argparse.ArgumentParser(description='Hash Decrypter')
    parser.add_argument('mode', type=str, choices=['hash', 'unhash'], help='Mode: hash or unhash')
    parser.add_argument('hash_type', type=str, help='Type of hash (sha1, sha224, md5)')
    parser.add_argument('hash_value', type=str, help='Hash value to decrypt' if 'unhash' in sys.argv else 'Text value to hash')
    args = parser.parse_args()

    if args.mode == 'crack':
        if args.hash_type == "sha1":
            sha1(args.hash_value)
        elif args.hash_type == "md5":
            md5(args.hash_value)
        elif args.hash_type == "sha224":
            sha224(args.hash_value)
        else:
            print("Invalid hash type. Please choose 'sha1' or 'md5'.")
    elif args.mode == 'hash':
        print(hash_text(args.hash_value, args.hash_type))

if __name__ == '__main__':
    main()
