"""
auth.py - Authentication System Module (FIXED VERSION)
Handles user registration and login with encrypted password storage

CRITICAL FIX: Login now uses DECRYPTION instead of re-encryption
to solve the RSA-OAEP non-determinism problem.
"""

import os
import base64
from encryption import MultiLayerEncryption
from keys import KeyManager


class AuthenticationSystem:
    """
    Manages user registration and authentication using multi-layer encryption.
    Stores encrypted passwords in a text file using base64 encoding.
    
    FIXED: Login now properly decrypts stored password and compares hashes.
    """
    
    def __init__(self, storage_file="users.txt"):
        """
        Initialize the authentication system.
        
        Args:
            storage_file (str): Path to file for storing user credentials
        """
        self.storage_file = storage_file
        self.key_manager = KeyManager()
        
        # Initialize all cryptographic keys
        self.keys = self.key_manager.initialize_all_keys()
        
        # Create encryptor with BOTH public and private keys
        # Private key is needed for decryption during login
        self.encryptor = MultiLayerEncryption(
            self.keys['des_key'],
            self.keys['aes_key'],
            self.keys['rsa_public'],
            self.keys['rsa_private']  # CRITICAL: Include private key for decryption
        )
        
        # Create storage file if it doesn't exist
        if not os.path.exists(self.storage_file):
            with open(self.storage_file, 'w') as f:
                f.write("")  # Create empty file
            print(f"[+] Created new user storage file: {self.storage_file}")
    
    def load_users(self):
        """
        Load all users from the storage file.
        
        Returns:
            dict: Dictionary mapping usernames to encrypted passwords (base64 format)
        """
        users = {}
        
        try:
            with open(self.storage_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        username, encrypted_password_b64 = line.split(':', 1)
                        users[username] = encrypted_password_b64
        except FileNotFoundError:
            print(f"[!] Storage file not found: {self.storage_file}")
        except Exception as e:
            print(f"[!] Error loading users: {e}")
        
        return users
    
    def save_user(self, username, encrypted_password):
        """
        Save a new user to the storage file.
        
        Args:
            username (str): Username
            encrypted_password (bytes): Encrypted password data
        """
        try:
            # Convert encrypted password to base64 string for storage
            # Base64 is better than hex for binary data storage
            encrypted_password_b64 = base64.b64encode(encrypted_password).decode('utf-8')
            
            # Append to file
            with open(self.storage_file, 'a') as f:
                f.write(f"{username}:{encrypted_password_b64}\n")
            
            print(f"[+] User '{username}' saved successfully")
        except Exception as e:
            print(f"[!] Error saving user: {e}")
            raise
    
    def user_exists(self, username):
        """
        Check if a username already exists.
        
        Args:
            username (str): Username to check
            
        Returns:
            bool: True if user exists, False otherwise
        """
        users = self.load_users()
        return username in users
    
    def register(self, username, password):
        """
        Register a new user with username and password.
        
        Args:
            username (str): Desired username
            password (str): Plain text password
            
        Returns:
            tuple: (success: bool, message: str)
        """
        print(f"\n=== Registration Process for '{username}' ===")
        
        # Validate inputs
        if not username or not password:
            return False, "Username and password cannot be empty"
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        
        # Check if user already exists
        if self.user_exists(username):
            print(f"[!] Username '{username}' already exists")
            return False, "Username already exists"
        
        try:
            # Encrypt the password using multi-layer encryption
            # This creates: SHA-256 → DES → AES → RSA
            encrypted_password = self.encryptor.encrypt_password(password)
            
            # Save to storage file
            self.save_user(username, encrypted_password)
            
            print(f"=== Registration Successful ===\n")
            return True, "Registration successful"
            
        except Exception as e:
            print(f"[!] Registration failed: {e}")
            return False, f"Registration failed: {str(e)}"
    
    def login(self, username, password):
        """
        Authenticate a user with username and password.
        
        FIXED METHOD: Now uses DECRYPTION to solve RSA-OAEP non-determinism.
        
        How it works:
        1. Load the stored encrypted password
        2. DECRYPT it: RSA → AES → DES → get stored hash
        3. Hash the user's input password with SHA-256
        4. Compare the two hashes
        
        This fixes the bug where re-encrypting with RSA-OAEP always
        produces different ciphertext due to random padding.
        
        Args:
            username (str): Username
            password (str): Plain text password
            
        Returns:
            tuple: (success: bool, message: str)
        """
        print(f"\n=== Login Attempt for '{username}' ===")
        
        # Validate inputs
        if not username or not password:
            return False, "Username and password cannot be empty"
        
        # Load stored users
        users = self.load_users()
        
        # Check if user exists
        if username not in users:
            print(f"[!] Username '{username}' not found")
            return False, "Invalid username or password"
        
        try:
            # Get the stored encrypted password (base64 encoded)
            stored_encrypted_password_b64 = users[username]
            
            # Decode from base64 to bytes
            stored_encrypted_password = base64.b64decode(stored_encrypted_password_b64)
            
            print(f"[*] Stored encrypted password length: {len(stored_encrypted_password)} bytes")
            
            # CRITICAL FIX: Decrypt the stored password to get the original hash
            # This is the key difference from the broken version
            stored_hash = self.encryptor.decrypt_stored_password(stored_encrypted_password)
            
            # Hash the user's input password
            print(f"\n[*] Hashing user input password...")
            input_hash = self.encryptor.hash_password(password)
            
            # Compare the two hashes
            print(f"\n[*] Comparing hashes...")
            print(f"    Stored hash:  {stored_hash.hex()[:64]}...")
            print(f"    Input hash:   {input_hash.hex()[:64]}...")
            
            if stored_hash == input_hash:
                print(f"[+] Password match! Login successful")
                print(f"=== Login Successful ===\n")
                return True, "Login successful"
            else:
                print(f"[!] Password mismatch! Login failed")
                print(f"=== Login Failed ===\n")
                return False, "Invalid username or password"
                
        except Exception as e:
            print(f"[!] Login error: {e}")
            import traceback
            traceback.print_exc()
            return False, f"Login failed: {str(e)}"
    
    def get_user_count(self):
        """
        Get the total number of registered users.
        
        Returns:
            int: Number of registered users
        """
        users = self.load_users()
        return len(users)
    
    def list_users(self):
        """
        Get a list of all registered usernames.
        
        Returns:
            list: List of usernames
        """
        users = self.load_users()
        return list(users.keys())


# Test function for standalone execution
if __name__ == "__main__":
    print("Testing FIXED Authentication System...")
    print("="*60)
    
    # Create authentication system
    auth = AuthenticationSystem(storage_file="test_users.txt")
    
    # Test registration
    print("\n" + "="*60)
    print("TEST 1: Register new user")
    print("="*60)
    success, msg = auth.register("testuser", "password123")
    print(f"Result: {msg}\n")
    
    # Test duplicate registration
    print("="*60)
    print("TEST 2: Register duplicate user")
    print("="*60)
    success, msg = auth.register("testuser", "password123")
    print(f"Result: {msg}\n")
    
    # Test successful login (THIS SHOULD NOW WORK!)
    print("="*60)
    print("TEST 3: Login with correct password (CRITICAL TEST)")
    print("="*60)
    success, msg = auth.login("testuser", "password123")
    print(f"Result: {msg}")
    if success:
        print("✓ LOGIN FIX SUCCESSFUL!")
    else:
        print("✗ LOGIN STILL BROKEN!")
    print()
    
    # Test failed login
    print("="*60)
    print("TEST 4: Login with incorrect password")
    print("="*60)
    success, msg = auth.login("testuser", "wrongpassword")
    print(f"Result: {msg}\n")
    
    # Test non-existent user
    print("="*60)
    print("TEST 5: Login with non-existent user")
    print("="*60)
    success, msg = auth.login("nonexistent", "password123")
    print(f"Result: {msg}\n")
    
    print("="*60)
    print(f"Total registered users: {auth.get_user_count()}")
    print(f"User list: {auth.list_users()}")
    print("="*60)
