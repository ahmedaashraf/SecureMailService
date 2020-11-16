from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

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
    email = forms.EmailField(required=True)
    modulus_length = 256*4 # use larger value in production
	privatekey = RSA.generate(modulus_length, Random.new().read)
	publickey = privatekey.publickey()
    f = open ("public.txt", "w")
    f.write(publickey.exportKey())
    f.close()
    #publickey = forms.CharField(max_length=255, label='Public Key',required=True)
    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "publickey")

    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user
    
    
