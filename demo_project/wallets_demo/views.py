from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from .models import User
from dj_wallet.models import Transaction, Wallet
from decimal import Decimal

@login_required
def dashboard(request):
    # Get the user's default wallet
    wallet = request.user.wallet
    
    # Get recent transactions for this wallet
    # The dj_wallet Transaction model has a 'wallet' field
    transactions = Transaction.objects.filter(wallet=wallet).order_by('-created_at')[:10]
    
    return render(request, 'wallets_demo/dashboard.html', {
        'transactions': transactions
    })

@login_required
def deposit(request):
    if request.method == 'POST':
        amount = Decimal(request.POST.get('amount'))
        description = request.POST.get('description', 'Manual Deposit')
        
        try:
            with transaction.atomic():
                request.user.deposit(amount, meta={'description': description})
                messages.success(request, f'Successfully deposited ${amount}.')
                return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error during deposit: {str(e)}')
            
    return render(request, 'wallets_demo/deposit.html')

@login_required
def withdraw(request):
    if request.method == 'POST':
        amount = Decimal(request.POST.get('amount'))
        description = request.POST.get('description', 'Manual Withdrawal')
        
        try:
            if request.user.balance < amount:
                messages.error(request, 'Insufficient funds.')
            else:
                with transaction.atomic():
                    request.user.withdraw(amount, meta={'description': description})
                    messages.success(request, f'Successfully withdrew ${amount}.')
                    return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error during withdrawal: {str(e)}')
            
    return render(request, 'wallets_demo/withdraw.html')

@login_required
def transfer(request):
    users = User.objects.exclude(id=request.user.id)
    
    if request.method == 'POST':
        recipient_id = request.POST.get('recipient')
        amount = Decimal(request.POST.get('amount'))
        description = request.POST.get('description', 'Wallet Transfer')
        
        try:
            recipient = User.objects.get(id=recipient_id)
            if request.user.balance < amount:
                messages.error(request, 'Insufficient funds.')
            else:
                with transaction.atomic():
                    # dj-wallet has a transfer method
                    request.user.transfer(recipient, amount, meta={'description': description})
                    messages.success(request, f'Successfully transferred ${amount} to {recipient.username}.')
                    return redirect('dashboard')
        except User.DoesNotExist:
            messages.error(request, 'Recipient not found.')
        except Exception as e:
            messages.error(request, f'Error during transfer: {str(e)}')
            
    return render(request, 'wallets_demo/transfer.html', {'users': users})

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists.')
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                login(request, user)
                # Give new users a welcome bonus
                user.deposit(100, meta={'description': 'Welcome Bonus'})
                messages.success(request, 'Account created! You received a $100 welcome bonus.')
                return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error creating account: {str(e)}')
            
    return render(request, 'wallets_demo/register.html')
