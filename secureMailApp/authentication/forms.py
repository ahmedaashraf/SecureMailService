from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from authentication.models import sysuser

from Crypto import Random
from Crypto.PublicKey import RSA
import base64


def encrypt_message(a_message , publickey):
	encrypted_msg = publickey.encrypt(a_message.encode('utf-8'), 32)[0]
	encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
	return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, privatekey):
	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
	return decoded_decrypted_msg.decode("utf-8")

class NewUserForm(UserCreationForm):
    class Meta:
        model = sysuser
        fields = ("email", "password1", "password2")

    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)

        modulus_length = 256*4 
        privatekey = RSA.generate(modulus_length, Random.new().read) 
        publickey = privatekey.publickey()

        f = open("private.pem", "wb")
        f.write(privatekey.exportKey(format='PEM',passphrase=self.cleaned_data.get("password1")))
        f.close()

        f = open ("public.pem", "wb")
        f.write(publickey.exportKey())
        f.close()
        
        user.email = self.cleaned_data["email"]
        user.publickey = publickey
        if commit:
            user.save()
        return user
    
    
