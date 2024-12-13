from encryptor_signer import EncryptorSigner

def main():
    # Create file
    senstive_file = "senstive_file.txt"
    with open(senstive_file, "w") as f:
        f.write("This is a file with sensitive information.")
    print(f"\nCreated a senstive file: {senstive_file}")

    print("\nStep 2: Encrypting and signing file as Yousef...")
    encryptor = EncryptorSigner()
    
    try:
        encrypted_file, signature_file, metadata_file = encryptor.encrypt_and_sign(
            senstive_file, "Yousef", "yousefpass123"
        )
        print(f"✓ Created encrypted file: {encrypted_file}")
        print(f"✓ Created signature file: {signature_file}")
        print(f"✓ Created metadata file: {metadata_file}")
        print("\nFile has been encrypted and signed.")
        print("You can now proceed with verification and decryption.")
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Make sure you have generated keys first using 1_generate_keys.py")

if __name__ == "__main__":
    main()
