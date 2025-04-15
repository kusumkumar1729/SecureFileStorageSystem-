from django.db import models
from django.contrib.auth import get_user_model


User = get_user_model()

#Create Profile

class Profile(models.Model):
    user = models.ForeignKey(User , on_delete = models.CASCADE)
    id_user = models.IntegerField()
    
    
    def __str__(self):
        return self.user.username


