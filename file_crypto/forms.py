from django import forms

class FileUploadForm(forms.Form):
    file = forms.FileField(label="Select File")
    algorithm = forms.ChoiceField(
        choices=[("AES", "AES"), ("RSA", "RSA"), ("Blowfish", "Blowfish"), ("Hybrid", "Hybrid")],
        label="Encryption Algorithm"
    )
    password = forms.CharField(widget=forms.PasswordInput(), required=False, label="Password (For AES/Blowfish/Hybrid)")

class PasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(), required=True, label="Decryption Password")
