# Multi-Layer Password Authentication System

## Project Overview

This project implements a secure password authentication system using multi-layer encryption for a university course in **Principles of Cryptology**. The system employs a four-stage encryption pipeline: **SHA-256 → DES → AES → RSA** to protect user passwords.

## Team Members

- **Jana Mahmoud**
- **Islam Wahdan**
- **Malak Almohtady Bellah**

## System Architecture

### Encryption Pipeline

The system processes passwords through four sequential encryption layers:

1. **SHA-256 Hashing**: Converts the plain text password into a 256-bit hash
2. **DES Encryption**: Encrypts the hash using Data Encryption Standard (ECB mode)
3. **AES Encryption**: Further encrypts using Advanced Encryption Standard (ECB mode)
4. **RSA Encryption**: Final layer using RSA public-key encryption (PKCS1_OAEP padding)

### Why Multi-Layer Encryption?

Multi-layer encryption provides **defense in depth**:
- If one encryption layer is compromised, other layers still protect the data
- Combines symmetric (DES, AES) and asymmetric (RSA) encryption strengths
- Makes brute-force attacks computationally infeasible
- Provides both confidentiality and integrity

## Project Structure

```
cryptology_project/
├── keys.py           # Key generation and management
├── encryption.py     # Multi-layer encryption pipeline
├── auth.py          # Registration and login system
├── ui.py            # Tkinter graphical interface
├── main.py          # Application entry point
├── requirements.txt # Python dependencies
├── README.md        # This file
├── keys/            # Directory for storing cryptographic keys
│   ├── des_key.bin
│   ├── aes_key.bin
│   ├── rsa_private.pem
│   └── rsa_public.pem
└── users.txt        # Encrypted user credentials storage
```

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Setup Instructions

1. **Clone or download the project**:
   ```bash
   cd cryptology_project
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

## Usage

### Registration

1. Launch the application
2. Enter a username (minimum 3 characters)
3. Enter a password (minimum 6 characters)
4. Click **Register**
5. The system will:
   - Hash the password with SHA-256
   - Encrypt through DES → AES → RSA layers
   - Store the encrypted result in `users.txt`

### Login

1. Enter your registered username
2. Enter your password
3. Click **Login**
4. The system will:
   - Encrypt your password using the same pipeline
   - Compare with the stored encrypted value
   - Grant access if they match

## Module Documentation

### keys.py

**Purpose**: Manages cryptographic key generation and storage

**Key Classes**:
- `KeyManager`: Handles DES (8 bytes), AES (16 bytes), and RSA (2048-bit) keys

**Key Methods**:
- `generate_des_key()`: Creates random 8-byte DES key
- `generate_aes_key()`: Creates random 16-byte AES key
- `generate_rsa_keypair()`: Creates 2048-bit RSA key pair
- `load_*_key()`: Loads existing keys or generates new ones
- `initialize_all_keys()`: Sets up all required keys

### encryption.py

**Purpose**: Implements the multi-layer encryption pipeline

**Key Classes**:
- `MultiLayerEncryption`: Orchestrates the four-stage encryption process

**Key Methods**:
- `hash_password()`: SHA-256 hashing
- `encrypt_with_des()`: DES encryption with ECB mode and padding
- `encrypt_with_aes()`: AES encryption with ECB mode and padding
- `encrypt_with_rsa()`: RSA encryption with PKCS1_OAEP padding
- `encrypt_password()`: Complete pipeline execution

### auth.py

**Purpose**: Handles user registration and authentication

**Key Classes**:
- `AuthenticationSystem`: Manages user accounts and credential verification

**Key Methods**:
- `register()`: Creates new user account with encrypted password
- `login()`: Authenticates user by comparing encrypted passwords
- `load_users()`: Reads user data from storage file
- `save_user()`: Writes new user to storage file

### ui.py

**Purpose**: Provides graphical user interface

**Key Classes**:
- `AuthenticationUI`: Tkinter-based GUI for registration and login

**Features**:
- Clean, modern interface design
- Real-time status updates
- Input validation
- Error handling with user-friendly messages

### main.py

**Purpose**: Application entry point

**Functionality**:
- Displays welcome banner
- Initializes the system
- Launches the GUI
- Handles errors gracefully

## Security Considerations

### Strengths

- **Multi-layer defense**: Four independent encryption stages
- **Strong algorithms**: Industry-standard SHA-256, AES, and RSA
- **Key separation**: Different keys for each encryption layer
- **Proper padding**: PKCS padding for block ciphers
- **No plain text storage**: Passwords never stored in readable form

### Limitations

- **ECB mode**: Uses ECB mode for DES/AES (not recommended for production)
- **No salt**: SHA-256 hashing without salt (vulnerable to rainbow tables)
- **Key storage**: Keys stored in plain files (should use hardware security modules)
- **No key rotation**: Static keys (should implement periodic rotation)
- **File-based storage**: Simple text file (should use secure database)

### Production Recommendations

For real-world deployment, consider:
- Use CBC or GCM mode instead of ECB
- Add salt to password hashing (use bcrypt or Argon2)
- Implement secure key management (HSM, key vaults)
- Use encrypted database with access controls
- Add rate limiting and account lockout
- Implement multi-factor authentication
- Regular security audits and penetration testing

## Testing

Each module includes standalone testing functionality:

```bash
# Test key generation
python keys.py

# Test encryption pipeline
python encryption.py

# Test authentication system
python auth.py

# Test GUI (requires display)
python ui.py
```

## Technologies Used

- **Python 3**: Programming language
- **hashlib**: SHA-256 hashing (standard library)
- **pycryptodome**: DES, AES, RSA encryption
- **tkinter**: Graphical user interface (standard library)

## Academic Context

This project demonstrates:
- Understanding of cryptographic primitives
- Implementation of encryption algorithms
- Secure password storage techniques
- Software engineering best practices
- Team collaboration and task distribution

## License

This is an academic project for educational purposes.

## Contact

For questions or issues, please contact the team members through the course portal.
