from django.shortcuts import render, HttpResponse, redirect
from .models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login
import bcrypt

def index(request):
    print('RENDERING INDEX HTML')
    return render(request, "loginRegistration/index.html")

def registration(request):
    if request.method == 'POST':
        request.session.clear()
        errors = User.objects.registration_validator(request.POST)
        print(errors)
        if len(errors):
            for key, value in errors.items():
                messages.error(request,value)
            return redirect("/")
        else:
            hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            newUser = User.objects.create(f_name = request.POST['f_name'], l_name = request.POST['l_name'], email = request.POST['email'], pw_hash = hashed_pw, bday = request.POST['bday'])
            messages.success(request, 'Successfully registered!')
            request.session['id'] = newUser.id
            return redirect("/success")

def login(request):
    print('LOGIN INITIATING')
    if request.method == 'POST':
        request.session.clear()
        errors = User.objects.login_validator(request.POST)
        print(errors)
        if len(errors):
            for key, value in errors.items():
                messages.error(request,value)
            return redirect('/')
        else:
            request.session['id'] = User.objects.get(email = request.POST['email']).id
            print(request.session['id'])
            messages.success(request, 'Successfully logged in!')
            return redirect('/success')

def success(request):
    print('SUCCESS PAGE LOADING')
    if 'id' in session:
        user = User.objects.get(id = request.session['id'])
        print(user)
        context ={
            'user': user
        }
        return render(request, 'loginRegistration/success.html', context)
    else:
        return redirect('/')

def logout(request):
    print('LOGOUT')
    request.session.clear()
    return redirect('/')



