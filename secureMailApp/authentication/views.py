from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
# from .forms import MsgForm
from django.contrib.auth import login , logout, authenticate
from django.contrib import messages
from .forms import NewUserForm
from django.contrib.auth.decorators import login_required

def register(request):
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f"New account created: {username}")
            login(request, user)
            return redirect("/main")

        else:
            for msg in form.error_messages:
                messages.error(request, f"{msg}: {form.error_messages[msg]}")

            return render(request = request,
                          template_name = "authentication/register.html",
                          context={"form":form})

    form = NewUserForm
    return render(request = request,
                  template_name = "authentication/register.html",
                  context={"form":form})

def logout_request(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect("authentication:login")

def login_request(request):
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            request.session['password'] = password
            request.session['username'] = username

            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f"You are now logged in as {username}")
                return redirect('/main')
            else:
                messages.info(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    form = AuthenticationForm()
    return render(request = request,
                    template_name = "authentication/login.html",
                    context={"form":form})

# def msg(request):
#     form = MsgForm()
#     if request.method == 'POST':
#         form = MsgForm(request)
#         if form.is_valid():
#             password = request.session.get('password') 
#             sender_email = request.session.get('username')
#             form.save(request,sender_email, password)

#     return render(request=request,
#         template_name = "authentication/msg.html",
#         context={"form":form})

# def receive_msg(request):
#     pass
