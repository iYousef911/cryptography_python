from decryptor_verifier import DecryptorVerifier
from pathlib import Path

def main():
    print("\nStep 3: Verifying and decrypting file...")
    decryptor = DecryptorVerifier()
    
    # Find the encrypted file
    secure_files_dir = Path("secure_files")
    if not secure_files_dir.exists():
        print("Error: No encrypted files found.")
        print("Make sure you have encrypted files first using 2_encrypt_and_sign.py")
        return
        
    encrypted_files = list(secure_files_dir.glob("*_encrypted.txt"))
    if not encrypted_files:
        print("Error: No encrypted files found.")
        print("Make sure you have encrypted files first using 2_encrypt_and_sign.py")
        return
    
    encrypted_file = encrypted_files[0]
    
    try:
        # First verify signature only
        print("\nVerifying signature...")
        is_valid = decryptor.verify_only(encrypted_file, "Yousef", "yousefpass123")
        print(f"✓ Signature verification: {'Success' if is_valid else 'Failed'}")
        
        if is_valid:
            # Then decrypt if signature is valid
            print("\nDecrypting file...")
            decrypted_file = decryptor.verify_and_decrypt(encrypted_file, "Yousef", "yousefpass123")
            print(f"✓ Created decrypted file: {decrypted_file}")
            
            # Show decrypted contents
            print("\nDecrypted file contents:")
            with open(decrypted_file, 'r') as f:
                print(f.read())
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Make sure you have:")
        print("1. Generated keys using 1_generate_keys.py")
        print("2. Encrypted files using 2_encrypt_and_sign.py")

if __name__ == "__main__":
    main()
