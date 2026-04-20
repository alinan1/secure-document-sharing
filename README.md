# Secure Document Sharing System

## Overview
This project is a secure document sharing web application built with Flask.  
It allows users to upload, encrypt, store, and share documents with controlled access.

---

## Features
- User authentication (login/register)
- File upload with encryption
- Document sharing (viewer/editor permissions)
- Role-based access control (admin, user, guest)
- Version control for documents
- Audit trail and security logging
- HTTPS support (TLS encryption)

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/alinan1/secure-document-sharing.git
cd secure-document-sharing

### Create Virtual Environment
python3 -m venv venv
source venv/bin/activate   # Mac/Linux
# or
venv\Scripts\activate      # Windows

### Install requirements
git commit -m "Removed sensitive SSL files"

### Generate SSL Certificate for HTTPS
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

### Run code
python app.py

