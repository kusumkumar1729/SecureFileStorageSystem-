from django.db import models
from django.contrib.auth.models import User


class DeletedFile(models.Model):
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to="deleted_files/")
    deleted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.filename




class EncryptionHistory(models.Model):
    ACTION_CHOICES = (
        ('ENCRYPT', 'Encryption'),
        ('DECRYPT', 'Decryption'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    file_location = models.CharField(max_length=512)
    encryption_method = models.CharField(max_length=50)
    action_type = models.CharField(max_length=10, choices=ACTION_CHOICES, default='ENCRYPT')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.filename} - {self.encryption_method} - {self.action_type} - {self.user.username}"