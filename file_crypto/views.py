import os
import subprocess
import sys
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import models
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponse
from .aes_crypto import aes_encrypt, aes_decrypt
from .rsa_crypto import generate_rsa_keys, rsa_encrypt_file, rsa_decrypt_file
from .blowfish_crypto import blowfish_encrypt, blowfish_decrypt
from .hybrid_crypto import hybrid_encrypt, hybrid_decrypt
from .models import DeletedFile, EncryptionHistory


# Get the project base directory dynamically
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, "keys")  # Ensure keys are stored in the project folder
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
ATTEMPT_LIMIT = 5  # Maximum allowed password attempts

# Ensure the `keys` directory exists
os.makedirs(KEYS_DIR, exist_ok=True)


# Dictionary to track failed attempts
failed_attempts = {}

def ensure_rsa_keys():
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        generate_rsa_keys(KEYS_DIR)

def encrypt_file(request):
    try:
        if request.method == "POST":
            if "file" not in request.FILES:
                messages.error(request, "Please select a file to upload.")
                return redirect("encrypt")

            uploaded_file = request.FILES["file"]
            storage = FileSystemStorage()
            saved_name = storage.save(f"uploads/{uploaded_file.name}", uploaded_file)
            file_path = storage.path(saved_name)

            algorithm = request.POST.get("algorithm")
            password = request.POST.get("password", None)
            hybrid_choice = request.POST.get("hybrid_choice", None)

            if algorithm == "AES":
                aes_encrypt(file_path, password)
            elif algorithm == "RSA":
                ensure_rsa_keys()
                rsa_encrypt_file(file_path, PUBLIC_KEY_PATH)
            elif algorithm == "Blowfish":
                blowfish_encrypt(file_path, password)
            elif algorithm == "Hybrid":
                ensure_rsa_keys()
                hybrid_encrypt(file_path, hybrid_choice, password)

            EncryptionHistory.objects.create(
                user=request.user,
                filename=os.path.basename(file_path),
                file_location=file_path,
                encryption_method=algorithm if algorithm != "Hybrid" else f"Hybrid ({hybrid_choice})",
                action_type='ENCRYPT'
            )

            # Stream the encrypted file back to the user with the original filename
            return FileResponse(open(file_path, "rb"), as_attachment=True, filename=os.path.basename(file_path))

        return render(request, "encrypt.html")
    except Exception as e:
        messages.error(request, f"An error occurred during encryption: {e}")
        return redirect("encrypt")

def decrypt_file(request):
    try:
        if request.method == "POST":
            if "file" not in request.FILES:
                messages.error(request, "Please upload the encrypted file.")
                return redirect("decrypt")

            uploaded_file = request.FILES["file"]
            storage = FileSystemStorage()
            saved_name = storage.save(f"uploads/{uploaded_file.name}", uploaded_file)
            file_path = storage.path(saved_name)

            algorithm = request.POST.get("algorithm")
            password = request.POST.get("password", None)
            hybrid_choice = request.POST.get("hybrid_choice", None)

            if algorithm in ["RSA", "Hybrid"]:
                ensure_rsa_keys()

            if algorithm in ["RSA", "Hybrid"] and hybrid_choice and "RSA" in hybrid_choice:
                if not os.path.exists(PRIVATE_KEY_PATH):
                    messages.error(request, f"Private key not found! Expected at: {PRIVATE_KEY_PATH}")
                    return render(request, "decrypt.html")

            if file_path not in failed_attempts:
                failed_attempts[file_path] = 0

            success = False
            if algorithm == "AES":
                success = aes_decrypt(file_path, password)
            elif algorithm == "RSA":
                success = rsa_decrypt_file(file_path, PRIVATE_KEY_PATH)
            elif algorithm == "Blowfish":
                success = blowfish_decrypt(file_path, password)
            elif algorithm == "Hybrid":
                success = hybrid_decrypt(file_path, hybrid_choice, password)

            if success:
                failed_attempts[file_path] = 0
                EncryptionHistory.objects.create(
                    user=request.user,
                    filename=os.path.basename(file_path),
                    file_location=file_path,
                    encryption_method=algorithm if algorithm != "Hybrid" else f"Hybrid ({hybrid_choice})",
                    action_type='DECRYPT'
                )
                # Stream the decrypted file back to the user with the original filename
                return FileResponse(open(file_path, "rb"), as_attachment=True, filename=os.path.basename(file_path))
            else:
                failed_attempts[file_path] += 1
                remaining_attempts = ATTEMPT_LIMIT - failed_attempts[file_path]

                if remaining_attempts > 0:
                    messages.error(request, f"Incorrect password. {remaining_attempts} attempts left.")
                else:
                    messages.error(request, "Too many failed attempts! File will be deleted permanently.")
                    
                    with open(file_path, "rb") as f:
                        fs = FileSystemStorage()
                        saved_file = fs.save(f"deleted_files/{os.path.basename(file_path)}", f)
                        DeletedFile.objects.create(filename=os.path.basename(file_path), file=saved_file)
                    
                    os.remove(file_path)
                    del failed_attempts[file_path]
                    messages.error(request, "File deleted permanently due to multiple failed attempts.")

        return render(request, "decrypt.html")

    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {e}")
        return redirect("decrypt")

@login_required
def history(request):
    encrypt_history = EncryptionHistory.objects.filter(user=request.user, action_type='ENCRYPT').order_by('-timestamp')
    decrypt_history = EncryptionHistory.objects.filter(user=request.user, action_type='DECRYPT').order_by('-timestamp')
    return render(request, "history.html", {
        "encrypt_history": encrypt_history,
        "decrypt_history": decrypt_history
    })