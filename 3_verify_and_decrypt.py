# Import the DecryptorVerifier class from the decryptor_verifier module
from decryptor_verifier import DecryptorVerifier
from pathlib import Path

# Define the main function that will execute the verification and decryption process
def main():
    # Print a message indicating the start of the verification and decryption process
    print("\nStep 3: Verifying and decrypting file...")
    # Create an instance of the DecryptorVerifier class
    decryptor = DecryptorVerifier()
    
    # Specify the directory where encrypted files are stored
    secure_files_dir = Path("secure_files")
    # Check if the directory exists
    if not secure_files_dir.exists():
        # Print an error message if no encrypted files are found
        print("Error: No encrypted files found.")
        print("Make sure you have encrypted files first using 2_encrypt_and_sign.py")
        return
        
    # List all encrypted files in the directory
    encrypted_files = list(secure_files_dir.glob("*_encrypted.txt"))
    # Check if any encrypted files were found
    if not encrypted_files:
        # Print an error message if no encrypted files are found
        print("Error: No encrypted files found.")
        print("Make sure you have encrypted files first using 2_encrypt_and_sign.py")
        return
    
    # Select the first encrypted file from the list
    encrypted_file = encrypted_files[0]
    
    try:
        # Print a message indicating the start of signature verification
        print("\nVerifying signature...")
        # Verify the signature of the encrypted file
        is_valid = decryptor.verify_only(encrypted_file, "Yousef", "yousefpass123")
        # Print the result of the signature verification
        print(f"✓ Signature verification: {'Success' if is_valid else 'Failed'}")
        
        if is_valid:
            # Print a message indicating the start of the decryption process
            print("\nDecrypting file...")
            # Decrypt the file if the signature is valid
            decrypted_file = decryptor.verify_and_decrypt(encrypted_file, "Yousef", "yousefpass123")
            # Print confirmation of the created decrypted file
            print(f"✓ Created decrypted file: {decrypted_file}")
            
            # Show the contents of the decrypted file
            print("\nDecrypted file contents:")
            with open(decrypted_file, 'r') as f:
                print(f.read())
    except Exception as e:
        # Print an error message if the verification/decryption process fails
        print(f"Error: {str(e)}")
        print("Make sure you have:")
        print("1. Generated keys using 1_generate_keys.py")
        print("2. Encrypted files using 2_encrypt_and_sign.py")

# Check if the script is being run directly (not imported)
if __name__ == "__main__":
    # Call the main function to execute the verification and decryption process
    main()
