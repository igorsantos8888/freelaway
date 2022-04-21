from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.messages import constants
from django.contrib import auth

def cadastro(request):
    if request.user.is_authenticated:
        return redirect('/jobs/encontrar_jobs')
    
    if request.method == 'GET':
        return render(request, 'cadastro.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        senha = request.POST.get('password')
        confirmar_senha = request.POST.get('confirm-password') 

        if not senha == confirmar_senha:
            messages.add_message(request, constants.ERROR, 'As senhas não coincidem')
            return redirect('/auth/cadastro')
        
        if len(senha) < 5:
            messages.add_message(request, constants.ERROR, 'A senha deve ter no minímo 5 caracter')
            return redirect('/auth/cadastro')
        
        
        if len(username.strip()) == 0 or len(senha.strip()) == 0:
            messages.add_message(request, constants.ERROR, 'Os campos não podem ser vazios')
            return redirect('/auth/cadastro')
        
        user = User.objects.filter(username = username)
        
        if user.exists():
            messages.add_message(request, constants.ERROR, 'Usuário já existe')
            return redirect('/auth/cadastro')
        
        try:
            user = User.objects.create_user(username=username, password=senha)
            messages.add_message(request, constants.SUCCESS, 'Usuário criado com sucesso')
            return redirect('/auth/login')
        except:
            messages.add_message(request, constants.ERROR, 'Erro interno do sistema')
            return redirect('/auth/cadastro')
            
def login(request):
    if request.user.is_authenticated:
        return redirect('/jobs/encontrar_jobs')
    
    if request.method == 'GET':
        return render(request, 'logar.html')
    elif request.method == 'POST':
        
        username = request.POST.get('username')
        senha = request.POST.get('password')
        
        usuario = auth.authenticate(username=username, password=senha)
        
        if not usuario:
            messages.add_message(request, constants.ERROR, 'Usuário ou senha inválidos')
            return redirect('/auth/login')
        else:
            auth.login(request, usuario)
            return redirect('/jobs/encontrar_jobs')
            
def sair(request):
    auth.logout(request)
    return redirect('/auth/login')