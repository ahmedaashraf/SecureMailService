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
import os 

from Crypto import Random
from Crypto.PublicKey.RSA import generate,importKey
from Crypto.Cipher import PKCS1_OAEP,AES,Salsa20
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64
import smtplib, ssl
from base64 import b64decode
import ast
import email

def encrypt_message(a_message , publickey):
    encryptor = PKCS1_OAEP.new(publickey)
    # print('-----------', encryptor.__hash__() , publickey.exportKey(format='OpenSSH'), '-----------')
    encrypted_msg = encryptor.encrypt(a_message)
    # print("ENCRYPTED MESSAGE : " , encrypted_msg)
    # encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
    return encrypted_msg

def decrypt_message(encoded_encrypted_msg, privatekey):
    default_length = 128
    length = len(encoded_encrypted_msg)
    # cipher = AES.new(privatekey,AES.MODE_ECB)
    cipher = PKCS1_OAEP.new(privatekey)
    # print('-----',type(cipher),type(privatekey),encoded_encrypted_msg,'---------')
    # print('--------------',cipher.__hash__(),privatekey.exportKey(format='PEM'),'------------------')
    # print(length)
    if length <= default_length:
        decrypt_byte = cipher.decrypt(encoded_encrypted_msg)
    else:
        offset = 0
        res = []
        # print(length,offset,default_length)
        while length - offset > 0:
            if length - offset > default_length:
                chunked = encoded_encrypted_msg[offset: offset + default_length]
                print(chunked)
                res.append(cipher.decrypt(chunked))
            else:
                print("here")
                print(res)
                res.append(cipher.decrypt(encoded_encrypted_msg[offset:]))
            offset += default_length
        decrypt_byte = b''.join(res)
    # print(decrypt_byte)
    decrypted = decrypt_byte
    # print("DECRYPTED : " , decrypted)
    return decrypted

def sendemail(sender_email,sender_password,rec_email,subject,message,publickey):
    
    rnd = os.urandom(16)
    symmcipher = Salsa20.new(key=rnd)
    encrypted_msg = symmcipher.nonce + symmcipher.encrypt((subject+message).encode('utf-8'))
    # encrypted_msg = base64.b64encode(encrypted_msg)
    print('Msg : ', type(encrypted_msg),len(encrypted_msg),encrypted_msg,str(encrypted_msg))
    pkey = importKey(publickey[2:len(publickey)-1])
    encrypted_key = encrypt_message(rnd,pkey)
    # encrypted_key = base64.b64encode(encrypted_key)
    print('Key : ' , type(encrypted_key),len(encrypted_key),encrypted_key,str(encrypted_key))
    # Create a secure SSL context
    msg = email.message.EmailMessage()
    encryptedm = base64.b64encode(encrypted_key+encrypted_msg)
    print("Encrypted Msg : " , encryptedm,type(encryptedm),len(encryptedm),str(encryptedm))
    msg.set_content(str(encryptedm))
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = rec_email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, sender_password)
        server.send_message(msg)

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
            body = part.get_payload(decode=False)
    # print("HELLO------------------")
    # secret = raw["Subject"]
    # print(secret,len(secret),type(secret))
    # print(secret.encode('utf-8'))
    # print('BODY HERE :---------------------------', body[2:408], '----------------------------')
    # print(len(body.encode('utf-8')))
    # print(type(body))
    # print(len(body.decode('utf-8')))
    body = body.replace('=','')
    # print(msg)
    # msg = msg.replace(' ','')
    # print(msg)
    body = (str.join(" ", body.splitlines())).replace(' ','')
    # print(body)
    # print(body[2:-1])
    # print(body[2:-1])
    return body[2:-1]

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
    print(msg)
    newmsg = base64.b64decode(msg)
    print("TEST ME : " , newmsg, len(newmsg), type(newmsg))
    print('-----------------------')
    print("-------------- END OF MSG ---------------")
    
    file_key = open(f"private{request.user.email}.pem", "r")
    key = importKey(file_key.read(), passphrase=password)
    file_key.close()
    # print('----------',key,msg,'----------')
    
    secret = decrypt_message(newmsg[:128], key)
    # print("FINAL PART::::")
    # print(secret)
    # print(type(secret))
    # print(secret.decode('utf-8'))
    msg = newmsg[128:]
    # print(msg)
    noncem = msg[:8]
    ciphered = msg[8:]
    decryptor = Salsa20.new(key=secret,nonce=noncem)
    text = decryptor.decrypt(ciphered)

    return HttpResponse(text)