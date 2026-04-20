# Secure Document Sharing System

## Overview
This project is a secure document sharing web application built with Python Flask and uses HTML + CSS. 
It features Role Based access controls and allows users to upload, encrypt, store, and share documents.

## Features
- User authentication (login/register)
- File upload with encryption
- Document sharing (viewer/editor permissions)
- Role-based access control (admin, user, guest)
- Version control for documents
- Audit trail and security logging
- HTTPS support (TLS encryption)

## Setup Instructions

1. <b>Clone the repository:</b>
git clone https://github.com/alinan1/secure-document-sharing.git  
cd secure-document-sharing  

2. <b>Create a virtual environment:</b>
python3 -m venv venv  
source venv/bin/activate   (Mac/Linux)  
venv\Scripts\activate      (Windows)  

3. <b>Install dependencies:</b>
pip install -r requirements.txt  

4. <b>Delete current cert.pem and key.pem files and Generate new SSL certificate (for HTTPS):</b>
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365  

5. <b>Run the application:</b>
python app.py  

6. Open in browser:
https://127.0.0.1:5000  

Note: You may see a browser warning due to the self-signed certificate 
