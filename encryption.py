"""
encryption.py - Multi-Layer Encryption and Decryption Pipeline Module
Implements SHA-256 → DES → AES → RSA encryption chain
AND RSA → AES → DES → SHA-256 decryption chain for authentication
"""

import hashlib
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


class MultiLayerEncryption:
    """
    Implements a multi-layer encryption system using SHA-256 hashing
    followed by DES, AES, and RSA encryption.
    
    IMPORTANT: This class now includes DECRYPTION methods to fix the
    authentication bug caused by RSA-OAEP non-determinism.
    """
    
    def __init__(self, des_key, aes_key, rsa_public_key, rsa_private_key=None):
        """
        Initialize the encryption system with cryptographic keys.
        
        Args:
            des_key (bytes): 8-byte DES key
            aes_key (bytes): 16-byte AES key
            rsa_public_key (RSA key object): RSA public key for encryption
            rsa_private_key (RSA key object): RSA private key for decryption (optional)
        """
        self.des_key = des_key
        self.aes_key = aes_key
        self.rsa_public_key = rsa_public_key
        self.rsa_private_key = rsa_private_key
    
    # ========== ENCRYPTION METHODS ==========
    
    def hash_password(self, password):
        """
        Step 1: Hash the password using SHA-256.
        
        Args:
            password (str): Plain text password
            
        Returns:
            bytes: 32-byte SHA-256 hash
        """
        print(f"[1] Hashing password with SHA-256...")
        sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
        print(f"    SHA-256 hash length: {len(sha256_hash)} bytes")
        return sha256_hash
    
    def encrypt_with_des(self, data):
        """
        Step 2: Encrypt data using DES in ECB mode.
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            bytes: DES-encrypted data
        """
        print(f"[2] Encrypting with DES (ECB mode)...")
        
        # Create DES cipher in ECB mode
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        
        # Pad data to be multiple of 8 bytes (DES block size)
        padded_data = pad(data, DES.block_size)
        print(f"    Data padded to {len(padded_data)} bytes")
        
        # Encrypt the padded data
        encrypted_data = cipher.encrypt(padded_data)
        print(f"    DES encrypted length: {len(encrypted_data)} bytes")
        return encrypted_data
    
    def encrypt_with_aes(self, data):
        """
        Step 3: Encrypt data using AES in ECB mode.
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            bytes: AES-encrypted data
        """
        print(f"[3] Encrypting with AES (ECB mode)...")
        
        # Create AES cipher in ECB mode
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        
        # Pad data to be multiple of 16 bytes (AES block size)
        padded_data = pad(data, AES.block_size)
        print(f"    Data padded to {len(padded_data)} bytes")
        
        # Encrypt the padded data
        encrypted_data = cipher.encrypt(padded_data)
        print(f"    AES encrypted length: {len(encrypted_data)} bytes")
        return encrypted_data
    
    def encrypt_with_rsa(self, data):
        """
        Step 4: Encrypt data using RSA with PKCS1_OAEP padding.
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            bytes: RSA-encrypted data
        """
        print(f"[4] Encrypting with RSA (PKCS1_OAEP)...")
        
        # Create RSA cipher with OAEP padding
        cipher = PKCS1_OAEP.new(self.rsa_public_key)
        
        # RSA can only encrypt data smaller than key size
        # For 2048-bit RSA with OAEP, max data size is ~190 bytes
        # We need to split data into chunks if it's larger
        max_chunk_size = 190  # Safe size for 2048-bit RSA with OAEP
        encrypted_chunks = []
        
        # Split data into chunks and encrypt each
        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i + max_chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_chunks.append(encrypted_chunk)
        
        # Combine all encrypted chunks
        encrypted_data = b''.join(encrypted_chunks)
        print(f"    RSA encrypted length: {len(encrypted_data)} bytes")
        return encrypted_data
    
    def encrypt_password(self, password):
        """
        Complete encryption pipeline: SHA-256 → DES → AES → RSA.
        
        Args:
            password (str): Plain text password
            
        Returns:
            bytes: Final encrypted data after all layers
        """
        print(f"\n=== Starting Multi-Layer Encryption ===")
        print(f"Original password: {'*' * len(password)}")
        
        # Step 1: Hash with SHA-256
        hashed = self.hash_password(password)
        
        # Step 2: Encrypt with DES
        des_encrypted = self.encrypt_with_des(hashed)
        
        # Step 3: Encrypt with AES
        aes_encrypted = self.encrypt_with_aes(des_encrypted)
        
        # Step 4: Encrypt with RSA
        rsa_encrypted = self.encrypt_with_rsa(aes_encrypted)
        
        print(f"=== Encryption Complete ===\n")
        print(f"Final encrypted data length: {len(rsa_encrypted)} bytes")
        
        return rsa_encrypted
    
    # ========== DECRYPTION METHODS (NEW - FIXES LOGIN BUG) ==========
    
    def decrypt_with_rsa(self, encrypted_data):
        """
        Step 1 (Reverse): Decrypt RSA-encrypted data using private key.
        
        Args:
            encrypted_data (bytes): RSA-encrypted data
            
        Returns:
            bytes: Decrypted data (AES ciphertext)
        """
        if self.rsa_private_key is None:
            raise ValueError("RSA private key is required for decryption")
        
        print(f"[1] Decrypting with RSA (PKCS1_OAEP)...")
        
        # Create RSA cipher with OAEP padding
        cipher = PKCS1_OAEP.new(self.rsa_private_key)
        
        # RSA encrypted data comes in 256-byte chunks (for 2048-bit key)
        chunk_size = 256
        decrypted_chunks = []
        
        # Decrypt each chunk
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_chunks.append(decrypted_chunk)
        
        # Combine all decrypted chunks
        decrypted_data = b''.join(decrypted_chunks)
        print(f"    RSA decrypted length: {len(decrypted_data)} bytes")
        return decrypted_data
    
    def decrypt_with_aes(self, encrypted_data):
        """
        Step 2 (Reverse): Decrypt AES-encrypted data.
        
        Args:
            encrypted_data (bytes): AES-encrypted data
            
        Returns:
            bytes: Decrypted data (DES ciphertext)
        """
        print(f"[2] Decrypting with AES (ECB mode)...")
        
        # Create AES cipher in ECB mode
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        
        # Decrypt the data
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        # Remove padding
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        print(f"    AES decrypted length: {len(decrypted_data)} bytes")
        return decrypted_data
    
    def decrypt_with_des(self, encrypted_data):
        """
        Step 3 (Reverse): Decrypt DES-encrypted data.
        
        Args:
            encrypted_data (bytes): DES-encrypted data
            
        Returns:
            bytes: Decrypted data (SHA-256 hash)
        """
        print(f"[3] Decrypting with DES (ECB mode)...")
        
        # Create DES cipher in ECB mode
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        
        # Decrypt the data
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        # Remove padding
        decrypted_data = unpad(decrypted_padded, DES.block_size)
        print(f"    DES decrypted length: {len(decrypted_data)} bytes")
        return decrypted_data
    
    def decrypt_stored_password(self, encrypted_password):
        """
        Complete decryption pipeline: RSA → AES → DES → SHA-256 hash.
        
        This method is used during login to retrieve the stored hash
        from the encrypted password, which is then compared with the
        hash of the user's input.
        
        Args:
            encrypted_password (bytes): Final encrypted password from storage
            
        Returns:
            bytes: The original SHA-256 hash (32 bytes)
        """
        print(f"\n=== Starting Multi-Layer Decryption ===")
        print(f"Encrypted data length: {len(encrypted_password)} bytes")
        
        # Step 1: Decrypt with RSA (private key)
        aes_encrypted = self.decrypt_with_rsa(encrypted_password)
        
        # Step 2: Decrypt with AES
        des_encrypted = self.decrypt_with_aes(aes_encrypted)
        
        # Step 3: Decrypt with DES
        original_hash = self.decrypt_with_des(des_encrypted)
        
        print(f"=== Decryption Complete ===\n")
        print(f"Retrieved hash length: {len(original_hash)} bytes")
        
        return original_hash


# Test function for standalone execution
if __name__ == "__main__":
    from keys import KeyManager
    
    print("Testing Multi-Layer Encryption and Decryption...")
    
    # Initialize keys
    km = KeyManager()
    keys = km.initialize_all_keys()
    
    # Create encryption object with both public and private keys
    encryptor = MultiLayerEncryption(
        keys['des_key'],
        keys['aes_key'],
        keys['rsa_public'],
        keys['rsa_private']  # Now we include private key for decryption
    )
    
    # Test encryption
    test_password = "SecurePassword123!"
    print("\n" + "="*60)
    print("TEST: Encrypting password...")
    print("="*60)
    encrypted = encryptor.encrypt_password(test_password)
    
    print("\n" + "="*60)
    print("TEST: Decrypting password...")
    print("="*60)
    decrypted_hash = encryptor.decrypt_stored_password(encrypted)
    
    # Verify by hashing the original password and comparing
    original_hash = hashlib.sha256(test_password.encode('utf-8')).digest()
    
    print("\n" + "="*60)
    print("VERIFICATION:")
    print("="*60)
    print(f"Original hash:   {original_hash.hex()[:64]}...")
    print(f"Decrypted hash:  {decrypted_hash.hex()[:64]}...")
    print(f"Hashes match: {original_hash == decrypted_hash}")
    
    if original_hash == decrypted_hash:
        print("\n✓ SUCCESS: Encryption and decryption working correctly!")
    else:
        print("\n✗ FAILURE: Hash mismatch!")
