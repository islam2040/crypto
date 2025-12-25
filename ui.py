"""
ui.py - Modern Graphical User Interface Module (REDESIGNED)
Provides a beautiful Tkinter-based GUI with modern colors and styling
"""

import tkinter as tk
from tkinter import messagebox, ttk
from auth import AuthenticationSystem


class ModernAuthenticationUI:
    """
    Modern, professionally-designed graphical user interface for the 
    password authentication system with a beautiful color scheme.
    """
    
    def __init__(self):
        """Initialize the UI and authentication system."""
        self.auth_system = AuthenticationSystem()
        self.root = tk.Tk()
        self.root.title("Multi-Layer Password Authentication")
        self.root.geometry("600x550")
        self.root.resizable(False, False)
        
        # Modern color palette
        self.colors = {
            'primary': '#4A90E2',        # Soft blue
            'primary_dark': '#357ABD',   # Darker blue for hover
            'success': '#5CB85C',        # Green
            'success_dark': '#4CAF50',   # Darker green
            'danger': '#E74C3C',         # Red
            'bg_main': '#F5F7FA',        # Light grey-blue background
            'bg_card': '#FFFFFF',        # White card background
            'text_primary': '#2C3E50',   # Dark blue-grey text
            'text_secondary': '#7F8C8D', # Grey text
            'border': '#E1E8ED',         # Light border
            'shadow': '#BDC3C7'          # Shadow color
        }
        
        # Configure root window
        self.root.configure(bg=self.colors['bg_main'])
        
        # Create main interface
        self.create_widgets()
    
    def create_widgets(self):
        """Create and layout all UI widgets with modern styling."""
        
        # ========== HEADER SECTION ==========
        header_frame = tk.Frame(
            self.root, 
            bg=self.colors['primary'],
            height=120
        )
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Title with icon-like symbol
        title_label = tk.Label(
            header_frame,
            text="🔐 Password Authentication",
            font=("Segoe UI", 24, "bold"),
            bg=self.colors['primary'],
            fg='white'
        )
        title_label.pack(pady=(25, 5))
        
        # Subtitle
        subtitle_label = tk.Label(
            header_frame,
            text="Multi-Layer Encryption System",
            font=("Segoe UI", 11),
            bg=self.colors['primary'],
            fg='white'
        )
        subtitle_label.pack()
        
        # Technology badge
        tech_label = tk.Label(
            header_frame,
            text="SHA-256 • DES • AES • RSA",
            font=("Segoe UI", 9),
            bg=self.colors['primary_dark'],
            fg='white',
            padx=15,
            pady=3
        )
        tech_label.pack(pady=(8, 0))
        
        # ========== MAIN CONTENT CARD ==========
        # Create a "card" effect with padding and shadow
        card_container = tk.Frame(
            self.root,
            bg=self.colors['bg_main']
        )
        card_container.pack(fill=tk.BOTH, expand=True, padx=40, pady=30)
        
        # Main card
        card_frame = tk.Frame(
            card_container,
            bg=self.colors['bg_card'],
            relief=tk.FLAT,
            borderwidth=0
        )
        card_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add subtle border
        card_frame.config(highlightbackground=self.colors['border'], highlightthickness=1)
        
        # Content inside card with padding
        content_frame = tk.Frame(card_frame, bg=self.colors['bg_card'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=30)
        
        # ========== USERNAME FIELD ==========
        username_label = tk.Label(
            content_frame,
            text="Username",
            font=("Segoe UI", 11, "bold"),
            bg=self.colors['bg_card'],
            fg=self.colors['text_primary']
        )
        username_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 8))
        
        self.username_entry = tk.Entry(
            content_frame,
            font=("Segoe UI", 12),
            width=35,
            relief=tk.FLAT,
            borderwidth=0,
            bg='#F8F9FA',
            fg=self.colors['text_primary'],
            insertbackground=self.colors['primary']
        )
        self.username_entry.grid(row=1, column=0, pady=(0, 20), ipady=10)
        
        # Add border to entry
        self.username_entry.config(
            highlightbackground=self.colors['border'],
            highlightthickness=1
        )
        
        # ========== PASSWORD FIELD ==========
        password_label = tk.Label(
            content_frame,
            text="Password",
            font=("Segoe UI", 11, "bold"),
            bg=self.colors['bg_card'],
            fg=self.colors['text_primary']
        )
        password_label.grid(row=2, column=0, sticky=tk.W, pady=(0, 8))
        
        self.password_entry = tk.Entry(
            content_frame,
            font=("Segoe UI", 12),
            width=35,
            show="●",  # Modern bullet character
            relief=tk.FLAT,
            borderwidth=0,
            bg='#F8F9FA',
            fg=self.colors['text_primary'],
            insertbackground=self.colors['primary']
        )
        self.password_entry.grid(row=3, column=0, pady=(0, 30), ipady=10)
        
        # Add border to entry
        self.password_entry.config(
            highlightbackground=self.colors['border'],
            highlightthickness=1
        )
        
        # ========== BUTTONS ==========
        buttons_frame = tk.Frame(content_frame, bg=self.colors['bg_card'])
        buttons_frame.grid(row=4, column=0, pady=(0, 20))
        
        # Register button (outlined style)
        self.register_button = tk.Button(
            buttons_frame,
            text="Create Account",
            font=("Segoe UI", 11, "bold"),
            bg=self.colors['bg_card'],
            fg=self.colors['primary'],
            width=16,
            height=2,
            relief=tk.FLAT,
            cursor="hand2",
            borderwidth=2,
            command=self.handle_register
        )
        self.register_button.config(
            highlightbackground=self.colors['primary'],
            highlightthickness=2
        )
        self.register_button.pack(side=tk.LEFT, padx=8)
        
        # Add hover effects for register button
        self.register_button.bind('<Enter>', lambda e: self.on_button_hover(self.register_button, 'register'))
        self.register_button.bind('<Leave>', lambda e: self.on_button_leave(self.register_button, 'register'))
        
        # Login button (filled style)
        self.login_button = tk.Button(
            buttons_frame,
            text="Sign In",
            font=("Segoe UI", 11, "bold"),
            bg=self.colors['primary'],
            fg='white',
            width=16,
            height=2,
            relief=tk.FLAT,
            cursor="hand2",
            borderwidth=0,
            command=self.handle_login
        )
        self.login_button.pack(side=tk.LEFT, padx=8)
        
        # Add hover effects for login button
        self.login_button.bind('<Enter>', lambda e: self.on_button_hover(self.login_button, 'login'))
        self.login_button.bind('<Leave>', lambda e: self.on_button_leave(self.login_button, 'login'))
        
        # ========== STATUS LABEL ==========
        self.status_label = tk.Label(
            content_frame,
            text="",
            font=("Segoe UI", 10),
            bg=self.colors['bg_card'],
            fg=self.colors['text_secondary'],
            wraplength=400
        )
        self.status_label.grid(row=5, column=0, pady=(10, 0))
        
        # ========== FOOTER ==========
        footer_frame = tk.Frame(self.root, bg=self.colors['bg_main'], height=50)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)
        footer_frame.pack_propagate(False)
        
        footer_label = tk.Label(
            footer_frame,
            text="Cryptology Project • Team: Jana Mahmoud, Islam Wahdan, Malak Almohtady Bellah",
            font=("Segoe UI", 9),
            bg=self.colors['bg_main'],
            fg=self.colors['text_secondary']
        )
        footer_label.pack(pady=15)
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.handle_login())
        
        # Focus on username field
        self.username_entry.focus()
    
    def on_button_hover(self, button, button_type):
        """Handle button hover effect."""
        if button_type == 'login':
            button.config(bg=self.colors['primary_dark'])
        elif button_type == 'register':
            button.config(bg='#F0F8FF')  # Light blue background
    
    def on_button_leave(self, button, button_type):
        """Handle button leave effect."""
        if button_type == 'login':
            button.config(bg=self.colors['primary'])
        elif button_type == 'register':
            button.config(bg=self.colors['bg_card'])
    
    def get_credentials(self):
        """
        Get username and password from input fields.
        
        Returns:
            tuple: (username, password)
        """
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        return username, password
    
    def clear_fields(self):
        """Clear all input fields."""
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
    
    def update_status(self, message, status_type='info'):
        """
        Update the status label with color coding.
        
        Args:
            message (str): Status message to display
            status_type (str): 'success', 'error', or 'info'
        """
        colors = {
            'success': self.colors['success'],
            'error': self.colors['danger'],
            'info': self.colors['text_secondary']
        }
        self.status_label.config(text=message, fg=colors.get(status_type, colors['info']))
    
    def show_success_message(self, title, message):
        """Show a styled success message box."""
        messagebox.showinfo(title, message, icon='info')
    
    def show_error_message(self, title, message):
        """Show a styled error message box."""
        messagebox.showerror(title, message, icon='error')
    
    def show_warning_message(self, title, message):
        """Show a styled warning message box."""
        messagebox.showwarning(title, message, icon='warning')
    
    def handle_register(self):
        """Handle registration button click."""
        username, password = self.get_credentials()
        
        if not username or not password:
            self.show_warning_message("Input Required", "Please enter both username and password")
            return
        
        # Disable buttons during processing
        self.register_button.config(state=tk.DISABLED)
        self.login_button.config(state=tk.DISABLED)
        self.update_status("Creating account...", 'info')
        self.root.update()
        
        try:
            # Attempt registration
            success, message = self.auth_system.register(username, password)
            
            if success:
                self.show_success_message(
                    "Account Created", 
                    f"Welcome, {username}!\n\nYour account has been created successfully.\nYou can now sign in."
                )
                self.update_status(f"✓ Account created successfully", 'success')
                self.clear_fields()
                self.username_entry.focus()
            else:
                self.show_error_message("Registration Failed", message)
                self.update_status(f"✗ {message}", 'error')
        
        except Exception as e:
            self.show_error_message("Error", f"An unexpected error occurred:\n{str(e)}")
            self.update_status(f"✗ Error: {str(e)}", 'error')
        
        finally:
            # Re-enable buttons
            self.register_button.config(state=tk.NORMAL)
            self.login_button.config(state=tk.NORMAL)
    
    def handle_login(self):
        """Handle login button click."""
        username, password = self.get_credentials()
        
        if not username or not password:
            self.show_warning_message("Input Required", "Please enter both username and password")
            return
        
        # Disable buttons during processing
        self.register_button.config(state=tk.DISABLED)
        self.login_button.config(state=tk.DISABLED)
        self.update_status("Authenticating...", 'info')
        self.root.update()
        
        try:
            # Attempt login (NOW FIXED!)
            success, message = self.auth_system.login(username, password)
            
            if success:
                self.show_success_message(
                    "Login Successful", 
                    f"Welcome back, {username}!\n\nYou have been successfully authenticated."
                )
                self.update_status(f"✓ Welcome back, {username}!", 'success')
                self.clear_fields()
                self.username_entry.focus()
            else:
                self.show_error_message("Login Failed", message)
                self.update_status(f"✗ {message}", 'error')
                # Clear password field on failed login
                self.password_entry.delete(0, tk.END)
                self.password_entry.focus()
        
        except Exception as e:
            self.show_error_message("Error", f"An unexpected error occurred:\n{str(e)}")
            self.update_status(f"✗ Error: {str(e)}", 'error')
        
        finally:
            # Re-enable buttons
            self.register_button.config(state=tk.NORMAL)
            self.login_button.config(state=tk.NORMAL)
    
    def run(self):
        """Start the GUI application."""
        print("\n" + "="*60)
        print("Starting Modern Authentication UI...")
        print("="*60)
        print(f"Registered users: {self.auth_system.get_user_count()}")
        print("="*60 + "\n")
        self.root.mainloop()


# Test function for standalone execution
if __name__ == "__main__":
    app = ModernAuthenticationUI()
    app.run()
