from django.db import models
from django.contrib.auth.models import User

# Create your models here.



class UserPasswords(models.Model):
    userID = models.ForeignKey(User,on_delete=models.CASCADE,related_name='UserPasswords')
    password = models.CharField(max_length=200,null=False,blank=False)
    saved_date = models.DateTimeField(auto_now_add=True)

   