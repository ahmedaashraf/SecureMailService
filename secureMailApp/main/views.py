from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login , logout, authenticate
from django.contrib import messages
from django.utils.translation import ugettext_lazy as _

from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from .forms import ContactForm

import hashlib

from Crypto import Random
from Crypto.PublicKey.RSA import generate,importKey
import base64
import smtplib, ssl

def encrypt_message(a_message , publickey):
	encrypted_msg = publickey.encrypt(a_message.encode('utf-8'), 32)[0]
	encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
	return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, privatekey):
	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
	return decoded_decrypted_msg.decode("utf-8")

def sendemail(sender_email,sender_password,rec_email,subject,message,publickey):
    print(publickey)
    pkey = importKey(publickey)
    encrypted_msg = encrypt_message("Subject:"+ subject + "\n\n\n" + message, pkey)
    # Create a secure SSL context
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, rec_email, encrypted_msg)


# @login_required(login_url='login/')
# def mainpage (request):
#     return render(request,template_name="main/main.html")

@login_required(login_url='login/')
def mainpage(request):
    if request.method == 'GET':
        form = ContactForm()
    else:
        form = ContactForm(request.POST)
        if form.is_valid():

            subject = form.cleaned_data['subject']
            rec_email = form.cleaned_data['to_email']
            message = form.cleaned_data['message']
            password = form.cleaned_data['password']

            User = get_user_model()
            publickey = list(User.objects.filter(email=rec_email).values())
            sendemail(request.user.email,password,rec_email,subject,message,publickey[0]['publickey'])

            # try:
            # except:
            #     return ValueError(_('Error Sending Msg'))
            
            return redirect('/success')
    return render(request,"main/email.html",{'form':form})

def successView(request):
    return HttpResponse('Message sent Successfully')