🔐 StegoForge

StegoForge is a secure image steganography platform built with Python, Flask, Pillow, and modern cryptographic techniques. The application enables users to hide and extract secret messages inside images while providing secure key exchange through Elliptic Curve Diffie-Hellman (ECDH) cryptography and user authentication for controlled access.

✨ Features
Hide secret messages inside images
Extract hidden messages from encoded images
Secure image-based communication
ECDH key pair generation
Shared secret generation between users
Public key fingerprint verification
User authentication and login protection
Session-based access control
Image upload and processing
Web-based user-friendly interface

🛠️ Technology Stack

Python
Flask
Pillow (PIL)
Cryptography Library
HTML
CSS
JavaScript

📂 Project Structure

stegoforge_v4/
│
├── app.py
├── requirements.txt
├── templates/
│   ├── index.html
│   └── login.html
├── utils/
│   ├── encoder.py
│   ├── decoder.py
│   └── ecdh.py
└── static/

🚀 Installation

git clone https://github.com/yourusername/StegoForge.git
cd StegoForge

pip install -r requirements.txt

python app.py

Open:

http://localhost:5000

🎯 Project Objectives

This project was developed to demonstrate the integration of:

Steganography
Secure communication
Cryptography
Web application development
Image processing
Authentication systems

🔒 Security Features

Password-protected access
Session management
ECDH secure key exchange
Public key fingerprint validation
Protected message transmission through image steganography
