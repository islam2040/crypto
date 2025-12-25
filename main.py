"""
main.py - Application Entry Point (FIXED VERSION)
Launches the Multi-Layer Password Authentication System with fixed login
"""

import sys
from ui import ModernAuthenticationUI


def print_banner():
    """Display application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     Multi-Layer Password Authentication System               ║
    ║                      FIXED VERSION                            ║
    ║                                                               ║
    ║     Encryption Pipeline: SHA-256 → DES → AES → RSA           ║
    ║     Authentication: RSA → AES → DES → SHA-256 (FIXED!)       ║
    ║                                                               ║
    ║     Team Members:                                             ║
    ║       • Jana Mahmoud                                          ║
    ║       • Islam Wahdan                                          ║
    ║       • Malak Almohtady Bellah                                ║
    ║                                                               ║
    ║     Course: Principles of Cryptology                          ║
    ║                                                               ║
    ║     CRITICAL FIX: Login now uses decryption-based            ║
    ║                   authentication instead of re-encryption     ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """
    Main entry point for the application.
    Initializes and launches the modern GUI.
    """
    try:
        # Print welcome banner
        print_banner()
        
        print("\n[*] Initializing application...")
        print("[*] Loading cryptographic keys...")
        print("[*] Starting modern graphical interface...\n")
        
        # Create and run the GUI application
        app = ModernAuthenticationUI()
        app.run()
        
        print("\n[*] Application closed successfully")
        
    except KeyboardInterrupt:
        print("\n\n[!] Application interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        print("[!] Please check that all dependencies are installed:")
        print("    pip install pycryptodome")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
