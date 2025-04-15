from django.urls import path
from .views import encrypt_file, decrypt_file , history

urlpatterns = [
    path("encrypt/", encrypt_file, name="encrypt"),
    path("decrypt/", decrypt_file, name="decrypt"),
    path('history/', history, name='history'),
    
]
