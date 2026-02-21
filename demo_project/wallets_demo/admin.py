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
    Merchant,
    MerchantCashflowEvent,
    MerchantLoyaltyEvent,
    MerchantLoyaltyProgram,
    MerchantWalletCapability,
    OperationCase,
    OperationCaseNote,
    TreasuryAccount,
    TreasuryTransferRequest,
    User,
)


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("username", "email", "wallet_type", "is_staff", "is_superuser", "is_active")
    list_filter = ("wallet_type", "is_staff", "is_superuser", "is_active", "groups")


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


@admin.register(Merchant)
class MerchantAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "status", "wallet_type", "settlement_currency", "is_government", "owner", "updated_at")
    list_filter = ("status", "wallet_type", "settlement_currency", "is_government")
    search_fields = ("code", "name", "contact_email")


@admin.register(MerchantLoyaltyProgram)
class MerchantLoyaltyProgramAdmin(admin.ModelAdmin):
    list_display = ("merchant", "is_enabled", "earn_rate", "redeem_rate", "updated_at")
    list_filter = ("is_enabled",)
    search_fields = ("merchant__code", "merchant__name")


@admin.register(MerchantWalletCapability)
class MerchantWalletCapabilityAdmin(admin.ModelAdmin):
    list_display = (
        "merchant",
        "supports_b2b",
        "supports_b2c",
        "supports_c2b",
        "supports_p2g",
        "supports_g2p",
        "updated_at",
    )
    list_filter = ("supports_b2b", "supports_b2c", "supports_c2b", "supports_p2g", "supports_g2p")
    search_fields = ("merchant__code", "merchant__name")


@admin.register(MerchantLoyaltyEvent)
class MerchantLoyaltyEventAdmin(admin.ModelAdmin):
    list_display = (
        "merchant",
        "customer",
        "event_type",
        "flow_type",
        "points",
        "amount",
        "currency",
        "reference",
        "created_at",
    )
    list_filter = ("event_type", "flow_type", "currency", "created_at")
    search_fields = ("merchant__code", "customer__username", "reference")


@admin.register(MerchantCashflowEvent)
class MerchantCashflowEventAdmin(admin.ModelAdmin):
    list_display = (
        "merchant",
        "flow_type",
        "amount",
        "currency",
        "from_user",
        "to_user",
        "counterparty_merchant",
        "reference",
        "created_at",
    )
    list_filter = ("flow_type", "currency", "created_at")
    search_fields = ("merchant__code", "reference", "from_user__username", "to_user__username")


@admin.register(OperationCase)
class OperationCaseAdmin(admin.ModelAdmin):
    list_display = (
        "case_no",
        "case_type",
        "priority",
        "status",
        "customer",
        "merchant",
        "assigned_to",
        "created_at",
    )
    list_filter = ("case_type", "priority", "status", "created_at")
    search_fields = ("case_no", "title", "customer__username", "merchant__code")


@admin.register(OperationCaseNote)
class OperationCaseNoteAdmin(admin.ModelAdmin):
    list_display = ("case", "created_by", "is_internal", "created_at")
    list_filter = ("is_internal", "created_at")
    search_fields = ("case__case_no", "created_by__username", "note")
