from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import ApprovalRequest, TreasuryAccount, TreasuryTransferRequest, User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("username", "email", "is_staff", "is_superuser", "is_active")
    list_filter = ("is_staff", "is_superuser", "is_active", "groups")


@admin.register(ApprovalRequest)
class ApprovalRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "action",
        "status",
        "amount",
        "maker",
        "checker",
        "source_user",
        "recipient_user",
        "created_at",
    )
    list_filter = ("action", "status", "created_at")
    search_fields = (
        "maker__username",
        "checker__username",
        "source_user__username",
        "recipient_user__username",
    )


@admin.register(TreasuryAccount)
class TreasuryAccountAdmin(admin.ModelAdmin):
    list_display = ("name", "currency", "balance", "is_active", "updated_at")
    list_filter = ("currency", "is_active")
    search_fields = ("name",)


@admin.register(TreasuryTransferRequest)
class TreasuryTransferRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "status",
        "amount",
        "from_account",
        "to_account",
        "maker",
        "checker",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = ("maker__username", "checker__username", "reason")
