# Multi-Layer Password Authentication System (FIXED VERSION)

## 🎯 Project Overview

This is the **corrected and improved** version of the Multi-Layer Password Authentication System for the **Principles of Cryptology** course. This version includes:

✅ **CRITICAL FIX**: Login now works correctly using decryption-based authentication  
✅ **Modern UI**: Completely redesigned Tkinter interface with professional styling  
✅ **Base64 Storage**: Improved data storage format  
✅ **Enhanced Error Handling**: Better debugging and error messages  

## 👥 Team Members

- **Jana Mahmoud**
- **Islam Wahdan**
- **Malak Almohtady Bellah**

## 🔧 What Was Fixed

### Critical Bug: Login Always Failed

**Problem**: The original implementation tried to verify login by re-encrypting the user's password and comparing it to the stored ciphertext. This **always failed** because RSA-OAEP is non-deterministic—it produces different ciphertext each time, even for the same input.

**Solution**: The login process now:
1. **Decrypts** the stored ciphertext using the reverse pipeline (RSA → AES → DES)
2. Retrieves the original SHA-256 hash
3. Hashes the user's input password
4. Compares the two hashes (which are deterministic)

This is the correct and secure way to authenticate users in this system.

### UI Improvements

The Tkinter interface has been completely redesigned with:
- Modern color palette (soft blues, whites, clean accents)
- Professional card-based layout
- Improved spacing and padding
- Hover effects on buttons
- Better visual feedback for success/error states
- Enhanced typography and visual hierarchy

## 🏗️ System Architecture

### Encryption Pipeline (Registration)

```
Plain Password
    ↓
SHA-256 Hash (32 bytes)
    ↓
DES Encryption (ECB mode, padded)
    ↓
AES Encryption (ECB mode, padded)
    ↓
RSA Encryption (PKCS1_OAEP, 2048-bit)
    ↓
Base64 Encoding
    ↓
Stored in users.txt
```

### Decryption Pipeline (Login)

```
Stored Ciphertext (Base64)
    ↓
Base64 Decoding
    ↓
RSA Decryption (Private Key)
    ↓
AES Decryption (Unpad)
    ↓
DES Decryption (Unpad)
    ↓
Original SHA-256 Hash
    ↓
Compare with Hash of User Input
```

## 📁 Project Structure

```
cryptology_project_fixed/
├── keys.py                    # Key generation and management
├── encryption.py              # Encryption AND decryption pipeline (FIXED)
├── auth.py                    # Registration and login (FIXED)
├── ui.py                      # Modern Tkinter GUI (REDESIGNED)
├── main.py                    # Application entry point
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── explanation.md             # Detailed explanation of fixes
├── task_distribution_updated.md  # Updated team workload
├── keys/                      # Cryptographic keys directory
│   ├── des_key.bin
│   ├── aes_key.bin
│   ├── rsa_private.pem
│   └── rsa_public.pem
└── users.txt                  # User database (created on first use)
```

## 🚀 Installation and Usage

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Installation

1. **Navigate to project directory**:
   ```bash
   cd cryptology_project_fixed
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

### Testing Individual Modules

You can test each module independently:

```bash
# Test key generation
python keys.py

# Test encryption and decryption (CRITICAL TEST)
python encryption.py

# Test authentication system (CRITICAL TEST)
python auth.py

# Test UI (requires display)
python ui.py
```

## 🎨 UI Features

### Modern Design Elements

- **Professional Color Scheme**: Soft blue primary color (#4A90E2) with clean white backgrounds
- **Card-Based Layout**: Content is presented in a clean card with subtle borders
- **Responsive Buttons**: Hover effects provide visual feedback
- **Status Indicators**: Color-coded success (green) and error (red) messages
- **Enhanced Typography**: Uses Segoe UI font with proper sizing and weights
- **Visual Hierarchy**: Clear distinction between primary and secondary elements

### User Experience

- **Intuitive Interface**: Simple two-button design (Create Account / Sign In)
- **Real-Time Feedback**: Status label updates during processing
- **Keyboard Support**: Press Enter to submit
- **Auto-Focus**: Username field is automatically focused on start
- **Clear Error Messages**: User-friendly error dialogs with helpful information

## 🔐 Security Features

### Strengths

- **Multi-Layer Defense**: Four independent encryption stages
- **Strong Algorithms**: Industry-standard SHA-256, AES, and RSA
- **Proper Decryption**: Correct authentication using decryption instead of re-encryption
- **Base64 Storage**: Safe encoding for binary data in text files
- **Key Separation**: Different keys for each encryption layer

### Limitations (Academic Context)

- **ECB Mode**: Uses ECB mode for DES/AES (not recommended for production)
- **No Salt**: SHA-256 hashing without salt (vulnerable to rainbow tables)
- **Key Storage**: Keys stored in plain files (should use HSM in production)
- **File-Based Storage**: Simple text file (should use encrypted database)

These limitations are intentional for educational purposes and are acknowledged in the project documentation.

## 📊 Testing Results

### Encryption/Decryption Test

```
✓ SUCCESS: Encryption and decryption working correctly!
  - Original hash matches decrypted hash
  - All layers functioning properly
```

### Authentication Test

```
✓ LOGIN FIX SUCCESSFUL!
  - Registration: Working
  - Login with correct password: Working
  - Login with incorrect password: Correctly rejected
  - Non-existent user: Correctly rejected
```

## 📚 Documentation

- **README.md** (this file): Complete project overview
- **explanation.md**: Detailed explanation of the RSA-OAEP bug and UI improvements
- **task_distribution_updated.md**: Updated team responsibilities

## 🎓 Academic Value

This project demonstrates:

✓ Understanding of cryptographic primitives  
✓ Proper implementation of encryption/decryption  
✓ Understanding of RSA-OAEP non-determinism  
✓ Secure password storage techniques  
✓ Software debugging and problem-solving  
✓ UI/UX design principles  
✓ Team collaboration and task distribution  

## 🔄 Key Differences from Original

| Aspect | Original | Fixed Version |
|--------|----------|---------------|
| Login Method | Re-encryption + comparison | Decryption + hash comparison |
| Login Success Rate | 0% (always fails) | 100% (works correctly) |
| Storage Format | Hex string | Base64 encoding |
| UI Design | Basic colors | Modern professional theme |
| Error Handling | Basic | Enhanced with detailed logging |
| Private Key Usage | Not used | Used for decryption |

## 🎯 How to Present This Project

1. **Demonstrate the Bug**: Show the original version failing to login
2. **Explain RSA-OAEP**: Explain why non-deterministic encryption breaks comparison
3. **Show the Fix**: Demonstrate the decryption-based approach
4. **Live Demo**: Register a user and successfully login
5. **UI Showcase**: Highlight the modern design improvements
6. **Code Walkthrough**: Show the key changes in `encryption.py` and `auth.py`

## 📝 License

This is an academic project for educational purposes.

## 📞 Contact

For questions about the project, please contact the team members through the course portal.

---

**Course**: Principles of Cryptology  
**Version**: 2.0 (Fixed)  
**Status**: ✅ Fully Functional
