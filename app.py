from flask import Flask, request, send_from_directory, render_template_string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Initialize Flask
app = Flask(__name__)

# Folder to store uploaded files
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Secret key (16, 24, or 32 bytes)
SECRET_KEY = b'MySecretKey12345'  # 16 bytes

# Encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()

    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted)
    
    # Optional: delete original file
    # os.remove(file_path)

# Decrypt a file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()

    iv = data[:16]
    encrypted = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    decrypted_path = file_path[:-4]  # remove .enc
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted)

    return decrypted_path

# Upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    encrypt_file(file_path, SECRET_KEY)
    return 'File uploaded and encrypted successfully', 200

# Download route
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    enc_file_path = os.path.join(UPLOAD_FOLDER, filename + '.enc')
    if not os.path.exists(enc_file_path):
        return 'File not found', 404

    decrypted_path = decrypt_file(enc_file_path, SECRET_KEY)

    # Serve file to browser
    response = send_from_directory(UPLOAD_FOLDER, os.path.basename(decrypted_path), as_attachment=True)

    # Delete decrypted file after sending
    os.remove(decrypted_path)

    return response

# Serve HTML form
@app.route('/form')
def form():
    return render_template_string(open('index.html').read())

# Run app
if __name__ == '__main__':
    app.run(debug=True)