from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import os
import json
import base64
import hmac as hmac_module
from pathlib import Path
from key_generator import KeyGenerator

class DecryptorVerifier:
    def __init__(self, output_dir="decrypted_files"):
        """Initialize the decryptor and verifier"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.key_generator = KeyGenerator()

    def verify_and_decrypt(self, encrypted_filepath, username, password):
        """
        Verify signature and decrypt a file
        
        Args:
            encrypted_filepath (str): Path to encrypted file
            username (str): Username of the decryptor
            password (str): Password to derive key from
            
        Returns:
            str: Path to decrypted file
        """
        encrypted_filepath = Path(encrypted_filepath)
        signature_filepath = encrypted_filepath.parent / f"{encrypted_filepath.stem.replace('_encrypted', '')}_signature.sig"
        metadata_filepath = encrypted_filepath.parent / f"{encrypted_filepath.stem.replace('_encrypted', '')}_metadata.json"

        # Load metadata
        with open(metadata_filepath, 'r') as f:
            metadata = json.load(f)

        # Get user's key pair
        user_key_pair = self.key_generator.load_key_pair(username, password)

        # Read encrypted data and signature
        with open(encrypted_filepath, 'rb') as f:
            encrypted_data = f.read()
        
        with open(signature_filepath, 'rb') as f:
            stored_signature = f.read()

        # Decrypt the symmetric key
        encrypted_symmetric_key = base64.b64decode(metadata['encrypted_symmetric_key'])
        symmetric_key = user_key_pair.decrypt(
            encrypted_symmetric_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Verify signature using public key
        try:
            user_key_pair.public_key().verify(
                stored_signature,
                encrypted_data,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✓ Signature verified")
        except Exception as e:
            raise ValueError("Invalid signature") from e

        # Decrypt the file
        iv = base64.b64decode(metadata['iv'])
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Decrypt and unpad
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Save decrypted file
        decrypted_filepath = self.output_dir / f"{metadata['filename']}"
        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)

        return decrypted_filepath

    def verify_only(self, encrypted_filepath, username, password):
        """
        Verify the signature of an encrypted file
        
        Args:
            encrypted_filepath (str): Path to encrypted file
            username (str): Username of the decryptor
            password (str): Password to derive key from
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        encrypted_filepath = Path(encrypted_filepath)
        signature_filepath = encrypted_filepath.parent / f"{encrypted_filepath.stem.replace('_encrypted', '')}_signature.sig"
        metadata_filepath = encrypted_filepath.parent / f"{encrypted_filepath.stem.replace('_encrypted', '')}_metadata.json"

        # Load metadata
        with open(metadata_filepath, 'r') as f:
            metadata = json.load(f)

        # Get user's key pair
        user_key_pair = self.key_generator.load_key_pair(username, password)

        # Read encrypted data and signature
        with open(encrypted_filepath, 'rb') as f:
            encrypted_data = f.read()
        
        with open(signature_filepath, 'rb') as f:
            stored_signature = f.read()

        # Verify signature using public key
        try:
            user_key_pair.public_key().verify(
                stored_signature,
                encrypted_data,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
