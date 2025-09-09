# 🔐 SecureFile Storage System

A robust and secure web application for file encryption and decryption using AES, RSA, Blowfish, and Hybrid encryption algorithms. The system also includes user authentication via **email OTP verification**, secure login, and security measures such as **file deletion after 3 failed decryption attempts**.

---

## 🚀 Features

- 🔐 **Encrypt & Decrypt Any File**
  - Supports `.txt`, `.pdf`, `.docx`, `.jpg`, `.png`, `.mp4`, etc.
  - Encryption algorithms:
    - **AES (Advanced Encryption Standard)**
    - **RSA (Rivest–Shamir–Adleman)**
    - **Blowfish**
    - **Hybrid** (combines symmetric & asymmetric encryption)

- 👨‍💻 **User Authentication**
  - Email-based **OTP verification** during registration
  - Secure **sign-in system**
  - Individual user dashboard

- 🧠 **Smart Security Logic**
  - If a user enters the wrong decryption PIN **3 times**, the file is **automatically deleted** for protection.

- 📁 Files are stored **locally** and replaced upon encryption/decryption, ensuring no unencrypted copy remains.

---

## 🔧 Technologies Used

- **Backend:** Django
- **Frontend:** HTML, CSS, JavaScript
- **Encryption Libraries:** `pycryptodome`, `cryptography`, `rsa`
- **Email OTP:** Python `smtplib`
- **Database:** SQLite (Django ORM)

---

## 🛡️ Encryption Algorithms

| Algorithm | Type     | Use Case                                     |
|----------|----------|-----------------------------------------------|
| AES      | Symmetric | Fast, suitable for large files               |
| RSA      | Asymmetric | Secure key exchange and small files         |
| Blowfish | Symmetric | Lightweight, fast, good for small-medium files |
| Hybrid   | Symmetric + Asymmetric | Combines AES + RSA for best performance and security |

---

## 🧪 Workflow

1. **Register** with your email and password
2. **Verify** your email with the OTP sent to your inbox
3. **Sign in** to your dashboard
4. Upload a file → Select encryption method → **Encrypt**
5. To decrypt:
   - Provide the correct PIN
   - If entered incorrectly **3 times**, the file will be **deleted**
6. Successfully decrypted files are restored in their original location

---

## 📽 Demo

https://github.com/user-attachments/assets/c28105cb-6b3e-42b8-8f5a-2759f253e33c

---


