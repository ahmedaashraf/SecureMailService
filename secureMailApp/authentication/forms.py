from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from authentication.models import sysuser

from Crypto import Random
from Crypto.PublicKey import RSA
import base64
import smtplib, ssl

class NewUserForm(UserCreationForm):
    class Meta:
        model = sysuser
        fields = ("email", "password1", "password2")

    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)

        modulus_length = 256*4 
        privatekey = RSA.generate(modulus_length, Random.new().read) 
        publickey = privatekey.publickey()

        f = open("private"+user.email+".pem", "wb")
        f.write(privatekey.exportKey(format='PEM',passphrase=self.cleaned_data.get("password1")))
        f.close()

        f = open ("public.pem", "wb")
        publickey = publickey.export_key(format='OpenSSH')
        f.write(publickey)
        f.close()
        
        user.email = self.cleaned_data["email"]
        user.publickey = publickey
        if commit:
            user.save()
        return user