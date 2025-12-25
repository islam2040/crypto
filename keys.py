"""
keys.py - Key Generation and Management Module
Handles generation, storage, and loading of DES, AES, and RSA keys
"""

import os
from Crypto.Cipher import DES, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class KeyManager:
    """
    Manages cryptographic keys for the multi-layer encryption system.
    Generates and stores DES (8 bytes), AES (16 bytes), and RSA (2048-bit) keys.
    """
    
    def __init__(self, keys_dir="keys"):
        """
        Initialize the KeyManager with a directory for storing keys.
        
        Args:
            keys_dir (str): Directory path where keys will be stored
        """
        self.keys_dir = keys_dir
        self.des_key_path = os.path.join(keys_dir, "des_key.bin")
        self.aes_key_path = os.path.join(keys_dir, "aes_key.bin")
        self.rsa_private_key_path = os.path.join(keys_dir, "rsa_private.pem")
        self.rsa_public_key_path = os.path.join(keys_dir, "rsa_public.pem")
        
        # Create keys directory if it doesn't exist
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
    
    def generate_des_key(self):
        """
        Generate a random 8-byte DES key.
        
        Returns:
            bytes: 8-byte DES key
        """
        des_key = get_random_bytes(8)  # DES requires 8-byte key
        with open(self.des_key_path, 'wb') as f:
            f.write(des_key)
        print(f"[+] DES key generated and saved to {self.des_key_path}")
        return des_key
    
    def generate_aes_key(self):
        """
        Generate a random 16-byte AES key (AES-128).
        
        Returns:
            bytes: 16-byte AES key
        """
        aes_key = get_random_bytes(16)  # AES-128 requires 16-byte key
        with open(self.aes_key_path, 'wb') as f:
            f.write(aes_key)
        print(f"[+] AES key generated and saved to {self.aes_key_path}")
        return aes_key
    
    def generate_rsa_keypair(self):
        """
        Generate a 2048-bit RSA key pair and save in PEM format.
        
        Returns:
            tuple: (private_key, public_key) RSA key objects
        """
        # Generate 2048-bit RSA key pair
        key = RSA.generate(2048)
        
        # Export private key in PEM format
        private_key = key.export_key()
        with open(self.rsa_private_key_path, 'wb') as f:
            f.write(private_key)
        
        # Export public key in PEM format
        public_key = key.publickey().export_key()
        with open(self.rsa_public_key_path, 'wb') as f:
            f.write(public_key)
        
        print(f"[+] RSA key pair generated and saved to {self.keys_dir}")
        return key, key.publickey()
    
    def load_des_key(self):
        """
        Load DES key from file. Generate if it doesn't exist.
        
        Returns:
            bytes: 8-byte DES key
        """
        if not os.path.exists(self.des_key_path):
            print("[!] DES key not found. Generating new key...")
            return self.generate_des_key()
        
        with open(self.des_key_path, 'rb') as f:
            des_key = f.read()
        print(f"[+] DES key loaded from {self.des_key_path}")
        return des_key
    
    def load_aes_key(self):
        """
        Load AES key from file. Generate if it doesn't exist.
        
        Returns:
            bytes: 16-byte AES key
        """
        if not os.path.exists(self.aes_key_path):
            print("[!] AES key not found. Generating new key...")
            return self.generate_aes_key()
        
        with open(self.aes_key_path, 'rb') as f:
            aes_key = f.read()
        print(f"[+] AES key loaded from {self.aes_key_path}")
        return aes_key
    
    def load_rsa_keys(self):
        """
        Load RSA key pair from PEM files. Generate if they don't exist.
        
        Returns:
            tuple: (private_key, public_key) RSA key objects
        """
        if not os.path.exists(self.rsa_private_key_path) or \
           not os.path.exists(self.rsa_public_key_path):
            print("[!] RSA keys not found. Generating new key pair...")
            return self.generate_rsa_keypair()
        
        # Load private key
        with open(self.rsa_private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read())
        
        # Load public key
        with open(self.rsa_public_key_path, 'rb') as f:
            public_key = RSA.import_key(f.read())
        
        print(f"[+] RSA keys loaded from {self.keys_dir}")
        return private_key, public_key
    
    def initialize_all_keys(self):
        """
        Initialize all keys (DES, AES, RSA) by loading or generating them.
        
        Returns:
            dict: Dictionary containing all keys
        """
        print("\n=== Initializing Cryptographic Keys ===")
        des_key = self.load_des_key()
        aes_key = self.load_aes_key()
        rsa_private, rsa_public = self.load_rsa_keys()
        print("=== Key Initialization Complete ===\n")
        
        return {
            'des_key': des_key,
            'aes_key': aes_key,
            'rsa_private': rsa_private,
            'rsa_public': rsa_public
        }


# Test function for standalone execution
if __name__ == "__main__":
    print("Testing Key Manager...")
    km = KeyManager()
    keys = km.initialize_all_keys()
    print("\nKeys initialized successfully!")
    print(f"DES Key Length: {len(keys['des_key'])} bytes")
    print(f"AES Key Length: {len(keys['aes_key'])} bytes")
    print(f"RSA Key Size: {keys['rsa_private'].size_in_bits()} bits")
