from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('fx/exchange/', views.wallet_fx_exchange, name='wallet_fx_exchange'),
    path('backoffice/', views.backoffice, name='backoffice'),
    path('backoffice/rbac/', views.rbac_management, name='rbac_management'),
    path('backoffice/fx/', views.fx_management, name='fx_management'),
    path('backoffice/accounting/', views.accounting_dashboard, name='accounting_dashboard'),
    path(
        'backoffice/accounting/entries/<int:entry_id>/post/',
        views.accounting_post_entry,
        name='accounting_post_entry',
    ),
    path('backoffice/treasury/', views.treasury_dashboard, name='treasury_dashboard'),
    path(
        'backoffice/treasury/<int:request_id>/decision/',
        views.treasury_decision,
        name='treasury_decision',
    ),
    path(
        'backoffice/approvals/<int:request_id>/decision/',
        views.approval_decision,
        name='approval_decision',
    ),
    path('deposit/', views.deposit, name='deposit'),
    path('withdraw/', views.withdraw, name='withdraw'),
    path('transfer/', views.transfer, name='transfer'),
    path('register/', views.register, name='register'),
    path('login/', views.portal_login, name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
]
