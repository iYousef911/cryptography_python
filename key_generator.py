from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
import base64
from pathlib import Path

class KeyGenerator:
    def __init__(self, keys_dir="keys"):
        """Initialize the key generator"""
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)

    def generate_key(self, username, password):
        """
        Generate an AES-256 key using password-based key derivation
        
        Args:
            username (str): Username for the key
            password (str): Password to derive the key from
            
        Returns:
            bytes: The generated key
        """
        # Generate a random salt
        salt = os.urandom(16)
        
        # Use PBKDF2 to derive the key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(password.encode())
        
        # Save key information
        key_info = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'username': username
        }
        
        # Create user directory and save key info
        user_dir = self.keys_dir / username
        user_dir.mkdir(exist_ok=True)
        
        with open(user_dir / "key_info.json", "w") as f:
            json.dump(key_info, f, indent=4)
        
        return key

    def load_key(self, username, password):
        """
        Load a user's key
        
        Args:
            username (str): Username to load key for
            password (str): Password to derive key from
            
        Returns:
            bytes: The loaded key
        """
        user_dir = self.keys_dir / username
        
        # Load key information
        with open(user_dir / "key_info.json", "r") as f:
            key_info = json.load(f)
        
        # Derive the key
        salt = base64.b64decode(key_info['salt'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return kdf.derive(password.encode())

    def generate_key_pair(self, username, password):
        """
        Generate an RSA key pair
        
        Args:
            username (str): Username for the key
            password (str): Password to encrypt the private key
            
        Returns:
            rsa.RSAPrivateKey: The generated private key
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Serialize private key with password encryption
        encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        # Serialize public key
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create user directory
        user_dir = self.keys_dir / username
        user_dir.mkdir(exist_ok=True)
        
        # Save keys
        with open(user_dir / "private_key.pem", "wb") as f:
            f.write(encrypted_pem)
        with open(user_dir / "public_key.pem", "wb") as f:
            f.write(public_pem)
        
        return private_key

    def load_key_pair(self, username, password):
        """
        Load RSA key pair for a user
        
        Args:
            username (str): Username to load key for
            password (str): Password to decrypt the private key
            
        Returns:
            rsa.RSAPrivateKey: The loaded private key
        """
        user_dir = self.keys_dir / username
        
        # Load private key
        with open(user_dir / "private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode()
            )
        
        return private_key
