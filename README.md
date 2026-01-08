# FUTURE_CS_01
# 🔐 Secure File Sharing System (Flask + AES Encryption)

A secure web-based file sharing system built using **Flask** and **AES-GCM encryption** to protect files both at rest and during transfer.  
This project simulates a real-world secure file handling environment such as **healthcare, legal, financial & corporate systems**.

---

## 🚀 Features
✔ Upload files securely  
✔ AES-GCM encryption (confidentiality + integrity)  
✔ Secure storage (encrypted files only)  
✔ Decryption only on download  
✔ Basic key management  
✔ Streaming encryption & decryption (supports large files)  
✔ Secure filename handling  
✔ File metadata tracking  
✔ Simple user-friendly interface  

---

## 🏗️ Tech Stack
Backend → Flask (Python)  
Encryption → PyCryptodome  
Frontend → HTML / CSS  
Testing Tools → Postman / Curl  
Language → Python 3  

---

## 📂 System Architecture
- User uploads file  
- System encrypts file using AES-GCM  
- Only encrypted version is stored  
- Metadata (nonce, tag, name) saved securely  
- When downloading → decrypted on-the-fly
- Integrity verified before release

🧾 Detailed design → `docs/architecture.md`

---

## 🔑 Security Model
- AES-256 GCM mode (Authenticated Encryption)
- Prevents tampering + ensures confidentiality
- Per-file nonce
- Secure key handling
- Restricted upload types
- Max upload size limit
- Sanitized filenames
- HTTPS recommended

📚 Full security explanation → `docs/security_model.md`
---
