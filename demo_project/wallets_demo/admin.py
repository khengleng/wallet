from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import (
    ApprovalRequest,
    BackofficeAuditLog,
    ChartOfAccount,
    FxRate,
    JournalEntry,
    JournalLine,
    LoginLockout,
    TreasuryAccount,
    TreasuryTransferRequest,
    User,
)


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


class JournalLineInline(admin.TabularInline):
    model = JournalLine
    extra = 0


@admin.register(ChartOfAccount)
class ChartOfAccountAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "account_type", "currency", "is_active")
    list_filter = ("account_type", "currency", "is_active")
    search_fields = ("code", "name")


@admin.register(JournalEntry)
class JournalEntryAdmin(admin.ModelAdmin):
    list_display = ("entry_no", "status", "reference", "created_by", "posted_by", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("entry_no", "reference", "description")
    inlines = [JournalLineInline]


@admin.register(BackofficeAuditLog)
class BackofficeAuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "actor", "target_type", "target_id", "ip_address")
    list_filter = ("action", "created_at")
    search_fields = ("actor__username", "target_type", "target_id")
    readonly_fields = (
        "actor",
        "action",
        "target_type",
        "target_id",
        "ip_address",
        "user_agent",
        "metadata_json",
        "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LoginLockout)
class LoginLockoutAdmin(admin.ModelAdmin):
    list_display = (
        "username",
        "ip_address",
        "failed_attempts",
        "first_failed_at",
        "lock_until",
        "updated_at",
    )
    list_filter = ("lock_until",)
    search_fields = ("username", "ip_address")


@admin.register(FxRate)
class FxRateAdmin(admin.ModelAdmin):
    list_display = (
        "base_currency",
        "quote_currency",
        "rate",
        "source_provider",
        "effective_at",
        "is_active",
        "created_by",
    )
    list_filter = ("base_currency", "quote_currency", "source_provider", "is_active")
    search_fields = ("base_currency", "quote_currency", "source_provider")
