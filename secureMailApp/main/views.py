from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login , logout, authenticate
from django.contrib import messages
from django.utils.translation import ugettext_lazy as _

from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from .forms import ContactForm
import rsa

import hashlib
import imaplib
import functools

from Crypto import Random
from Crypto.PublicKey.RSA import generate,importKey
from Crypto.Cipher import PKCS1_OAEP
import base64
import smtplib, ssl
from base64 import b64decode
import ast
import email

def encrypt_message(a_message , publickey):
    encryptor = PKCS1_OAEP.new(publickey)
    encrypted_msg = encryptor.encrypt(a_message.encode('utf-8'))
    # encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
    return encrypted_msg

def decrypt_message(encoded_encrypted_msg, privatekey):
    default_length = 128
    length = len(encoded_encrypted_msg)
    cipher = PKCS1_OAEP.new(privatekey) 
    if length < default_length:
        decrypt_byte = cipher.decrypt(encoded_encrypted_msg)
    else:
        offset = 0
        res = []
        while length - offset > 0:
            if length - offset > default_length:
                chunked = encoded_encrypted_msg[offset: offset + default_length]
                res.append(cipher.decrypt(chunked))
            else:
                print("here")
                print(res)
                # res.append(cipher.decrypt(encoded_encrypted_msg[offset:]))
            offset += default_length
        decrypt_byte = b''.join(res)
    decrypted = decrypt_byte.decode()
    return decrypted

def sendemail(sender_email,sender_password,rec_email,subject,message,publickey):
    # print(publickey)
    # print(type(publickey))
    pkey = importKey(publickey[2:len(publickey)-1])
    encrypted_msg = encrypt_message("Subject:"+ subject + "\n\n\n" + message, pkey)
    # Create a secure SSL context
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, rec_email, encrypted_msg)

def recmail(myemail, mypassword):
    mail = imaplib.IMAP4_SSL('imap.gmail.com')

    mail.login(myemail, mypassword)
    mail.list()
    # Out: list of "folders" aka labels in gmail.
    mail.select("inbox") # connect to inbox.
    result, data = mail.search(None, "ALL")

    ids = data[0] # data is a list.
    id_list = ids.split() # ids is a space separated string
    latest_email_id = id_list[-1] # get the latest

    result, data = mail.fetch(latest_email_id, "(RFC822)") # fetch the email body (RFC822) for the given ID

    raw_email = data[0][1] # here's the body, which is raw text of the whole email
    
    raw=email.message_from_bytes(data[0][1])

    for part in raw.walk():
        if part.get_content_type() == "text/plain":
            body = part.get_payload(decode=True)

    return body

# including headers and alternate payloads
# @login_required(login_url='login/')
# def mainpage (request):
#     return render(request,template_name="main/main.html")

@login_required(login_url='login/')
def mainpage(request):
    print(request.POST)
    if request.method == 'GET':
        form = ContactForm()
    elif 'send' in request.POST:
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
    elif 'inbox' in request.POST:
        request.session['password'] = request.POST['password']
        return redirect('/rec')

    return render(request,"main/email.html",{'form':form})

def successView(request):
    return HttpResponse('Message sent Successfully')

def recview(request):
    password = request.session['password']
    msg = recmail(request.user.email, password)
    file_key = open(f"private{request.user.email}.pem", "r")
    key = importKey(file_key.read(), passphrase=password)
    file_key.close()
    dec_msg = decrypt_message(msg, key)
    return HttpResponse(dec_msg)