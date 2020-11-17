from django.db import models
from django.contrib.auth.models import User
from django import forms
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import AbstractUser

from .managers import CustomUserManager
from picklefield.fields import PickledObjectField

# Create your models here.
class sysuser(AbstractUser):

    username = None
    email = models.EmailField(_('email address'),unique=True)
    publickey = PickledObjectField()
   
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    objects = CustomUserManager()

    def __str__(self):
        return self.email