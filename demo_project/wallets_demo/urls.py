from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('backoffice/', views.backoffice, name='backoffice'),
    path(
        'backoffice/approvals/<int:request_id>/decision/',
        views.approval_decision,
        name='approval_decision',
    ),
    path('deposit/', views.deposit, name='deposit'),
    path('withdraw/', views.withdraw, name='withdraw'),
    path('transfer/', views.transfer, name='transfer'),
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(template_name='wallets_demo/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
]
