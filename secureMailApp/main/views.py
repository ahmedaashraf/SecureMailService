from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login , logout, authenticate
from django.contrib import messages



@login_required(login_url='login/')
def mainpage (request):
    return render(request,template_name="main/main.html")

