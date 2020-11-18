from django import forms

##
class ContactForm(forms.Form):
    to_email = forms.EmailField(required=True)
    subject = forms.CharField(required=True)
    message = forms.CharField(widget=forms.Textarea,required=True)
    password = forms.CharField(widget=forms.PasswordInput)
    

# class MsgForm(forms.Form):
#     class Meta:
#         rec_email = forms.CharField(label='rec_mail', max_length=100)
#         msg_body  = forms.CharField(label='msg', max_length=100)

#     def save(self, request, sender_email, password):
#         # get user's pub key--lookup
#         rec_pub_key = "hi"
#         encrypted_msg = encrypt_message(request.POST['msg'], rec_pub_key)

        # # Create a secure SSL context
        # context = ssl.create_default_context()
        # with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        #     server.login(sender_email, password)
        #     server.sendmail(sender_email, request.POST['rec_email'], encrypted_msg)