from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import os
import json
import base64
from pathlib import Path
from key_generator import KeyGenerator

class EncryptorSigner:
    def __init__(self, output_dir="secure_files"):
        """Initialize the encryptor and signer"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.key_generator = KeyGenerator()

    def encrypt_and_sign(self, filepath, username, password):
        """
        Encrypt and sign a file
        
        Args:
            filepath (str): Path to file to encrypt
            username (str): Username of the encryptor
            password (str): User's password
            
        Returns:
            tuple: (encrypted_filepath, signature_filepath, metadata_filepath)
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File {filepath} not found")

        # Get user's key pair
        user_key_pair = self.key_generator.load_key_pair(username, password)
        
        # Read the file
        with open(filepath, 'rb') as f:
            data = f.read()

        # Generate a random symmetric key for this encryption
        symmetric_key = os.urandom(32)  # 256-bit key for AES-256
        
        # Generate IV
        iv = os.urandom(16)

        # Create cipher with symmetric key
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Add padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the data with symmetric key
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Create digital signature using private key
        signer = user_key_pair.sign(
            encrypted_data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Create metadata
        metadata = {
            'filename': filepath.name,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_symmetric_key': base64.b64encode(user_key_pair.public_key().encrypt(
                symmetric_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )).decode('utf-8'),
            'username': username,
            'timestamp': str(Path(filepath).stat().st_mtime)
        }

        # Save files
        encrypted_filepath = self.output_dir / f"{filepath.stem}_encrypted{filepath.suffix}"
        signature_filepath = self.output_dir / f"{filepath.stem}_signature.sig"
        metadata_filepath = self.output_dir / f"{filepath.stem}_metadata.json"
        
        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)
            
        with open(signature_filepath, 'wb') as f:
            f.write(signer)
            
        with open(metadata_filepath, 'w') as f:
            json.dump(metadata, f, indent=4)

        return encrypted_filepath, signature_filepath, metadata_filepath
