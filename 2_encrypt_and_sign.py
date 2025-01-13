# Import the EncryptorSigner class from the encryptor_signer module
from encryptor_signer import EncryptorSigner

# Define the main function that will execute the encryption and signing process
def main():
    # Specify the name of the sensitive file to be created
    senstive_file = "senstive_file.txt"
    # Create and write sensitive information to the file
    with open(senstive_file, "w") as f:
        f.write("This is a file with sensitive information.")
    # Print a message indicating the sensitive file has been created
    print(f"\nCreated a senstive file: {senstive_file}")

    # Print a message indicating the start of the encryption and signing process
    print("\nStep 2: Encrypting and signing file as Yousef...")
    # Create an instance of the EncryptorSigner class
    encryptor = EncryptorSigner()
    
    try:
        # Call the encrypt_and_sign method to encrypt the file and create signature and metadata files
        encrypted_file, signature_file, metadata_file = encryptor.encrypt_and_sign(
            senstive_file, "Yousef", "yousefpass123"
        )
        # Print confirmation messages for the created files
        print(f"✓ Created encrypted file: {encrypted_file}")
        print(f"✓ Created signature file: {signature_file}")
        print(f"✓ Created metadata file: {metadata_file}")
        # Print a message indicating the file has been encrypted and signed
        print("\nFile has been encrypted and signed.")
        print("You can now proceed with verification and decryption.")
    except Exception as e:
        # Print an error message if the encryption/signing process fails
        print(f"Error: {str(e)}")
        print("Make sure you have generated keys first using 1_generate_keys.py")

# Check if the script is being run directly (not imported)
if __name__ == "__main__":
    # Call the main function to execute the encryption and signing process
    main()
