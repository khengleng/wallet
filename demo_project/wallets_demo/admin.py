from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import (
    AccessReviewRecord,
    AccountingPeriodClose,
    AnalyticsEvent,
    ApprovalRequest,
    BackofficeAuditLog,
    ChartOfAccount,
    ChargebackCase,
    ChargebackEvidence,
    CustomerCIF,
    DisputeRefundRequest,
    FxRate,
    JournalEntry,
    JournalBackdateApproval,
    JournalLine,
    LoginLockout,
    Merchant,
    MerchantApiCredential,
    MerchantCashflowEvent,
    MerchantFeeRule,
    MerchantKYBRequest,
    MerchantLoyaltyEvent,
    MerchantLoyaltyProgram,
    MerchantRiskProfile,
    MerchantSettlementRecord,
    MerchantWebhookEvent,
    MerchantWalletCapability,
    ReconciliationBreak,
    ReconciliationRun,
    SanctionScreeningRecord,
    SettlementPayout,
    TransactionMonitoringAlert,
    OperationCase,
    OperationCaseNote,
    OperationSetting,
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


@admin.register(OperationSetting)
class OperationSettingAdmin(admin.ModelAdmin):
    list_display = ("organization_name", "merchant_id_prefix", "wallet_id_prefix", "transaction_id_prefix", "updated_at", "updated_by")
    readonly_fields = ("singleton_key", "created_at", "updated_at")


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
        "fee_amount",
        "net_amount",
        "currency",
        "from_user",
        "to_user",
        "counterparty_merchant",
        "reference",
        "settlement_reference",
        "settled_at",
        "created_at",
    )
    list_filter = ("flow_type", "currency", "created_at")
    search_fields = ("merchant__code", "reference", "from_user__username", "to_user__username")


@admin.register(MerchantKYBRequest)
class MerchantKYBRequestAdmin(admin.ModelAdmin):
    list_display = ("merchant", "status", "legal_name", "registration_number", "maker", "checker", "created_at")
    list_filter = ("status", "country_code", "created_at")
    search_fields = ("merchant__code", "legal_name", "registration_number", "tax_id")


@admin.register(MerchantFeeRule)
class MerchantFeeRuleAdmin(admin.ModelAdmin):
    list_display = (
        "merchant",
        "flow_type",
        "percent_bps",
        "fixed_fee",
        "minimum_fee",
        "maximum_fee",
        "is_active",
        "updated_at",
    )
    list_filter = ("flow_type", "is_active")
    search_fields = ("merchant__code",)


@admin.register(MerchantRiskProfile)
class MerchantRiskProfileAdmin(admin.ModelAdmin):
    list_display = (
        "merchant",
        "daily_txn_limit",
        "daily_amount_limit",
        "single_txn_limit",
        "reserve_ratio_bps",
        "require_manual_review_above",
        "is_high_risk",
        "updated_at",
    )
    list_filter = ("is_high_risk",)
    search_fields = ("merchant__code", "merchant__name")


@admin.register(MerchantApiCredential)
class MerchantApiCredentialAdmin(admin.ModelAdmin):
    list_display = ("merchant", "key_id", "scopes_csv", "is_active", "webhook_url", "last_rotated_at", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("merchant__code", "key_id", "webhook_url")
    readonly_fields = ("secret_hash",)


@admin.register(MerchantSettlementRecord)
class MerchantSettlementRecordAdmin(admin.ModelAdmin):
    list_display = (
        "settlement_no",
        "merchant",
        "currency",
        "period_start",
        "period_end",
        "gross_amount",
        "fee_amount",
        "net_amount",
        "event_count",
        "status",
        "approved_by",
        "created_at",
    )
    list_filter = ("status", "currency", "period_start", "period_end", "created_at")
    search_fields = ("settlement_no", "merchant__code")


@admin.register(DisputeRefundRequest)
class DisputeRefundRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "case",
        "merchant",
        "customer",
        "amount",
        "currency",
        "status",
        "maker",
        "checker",
        "created_at",
    )
    list_filter = ("status", "currency", "created_at")
    search_fields = ("case__case_no", "merchant__code", "customer__username", "reason")


@admin.register(SettlementPayout)
class SettlementPayoutAdmin(admin.ModelAdmin):
    list_display = (
        "payout_reference",
        "settlement",
        "payout_channel",
        "amount",
        "currency",
        "status",
        "initiated_by",
        "approved_by",
        "created_at",
    )
    list_filter = ("status", "currency", "payout_channel", "created_at")
    search_fields = ("payout_reference", "settlement__settlement_no", "settlement__merchant__code")


@admin.register(ReconciliationRun)
class ReconciliationRunAdmin(admin.ModelAdmin):
    list_display = (
        "run_no",
        "source",
        "currency",
        "period_start",
        "period_end",
        "internal_count",
        "external_count",
        "delta_count",
        "delta_amount",
        "status",
        "created_at",
    )
    list_filter = ("status", "source", "currency", "created_at")
    search_fields = ("run_no",)


@admin.register(ReconciliationBreak)
class ReconciliationBreakAdmin(admin.ModelAdmin):
    list_display = (
        "run",
        "merchant",
        "reference",
        "issue_type",
        "delta_amount",
        "status",
        "assigned_to",
        "resolved_by",
        "created_at",
    )
    list_filter = ("status", "issue_type", "created_at")
    search_fields = ("run__run_no", "merchant__code", "reference", "note")


@admin.register(ChargebackCase)
class ChargebackCaseAdmin(admin.ModelAdmin):
    list_display = (
        "chargeback_no",
        "case",
        "merchant",
        "customer",
        "reason_code",
        "amount",
        "currency",
        "status",
        "assigned_to",
        "due_at",
        "created_at",
    )
    list_filter = ("status", "currency", "reason_code", "created_at")
    search_fields = ("chargeback_no", "case__case_no", "merchant__code", "customer__username")


@admin.register(ChargebackEvidence)
class ChargebackEvidenceAdmin(admin.ModelAdmin):
    list_display = ("chargeback", "document_type", "document_url", "uploaded_by", "created_at")
    list_filter = ("document_type", "created_at")
    search_fields = ("chargeback__chargeback_no", "document_type", "document_url")


@admin.register(AccountingPeriodClose)
class AccountingPeriodCloseAdmin(admin.ModelAdmin):
    list_display = (
        "period_start",
        "period_end",
        "currency",
        "is_closed",
        "closed_by",
        "closed_at",
        "created_by",
        "updated_at",
    )
    list_filter = ("currency", "is_closed", "period_start", "period_end")
    search_fields = ("currency",)


@admin.register(JournalBackdateApproval)
class JournalBackdateApprovalAdmin(admin.ModelAdmin):
    list_display = (
        "entry",
        "requested_date",
        "status",
        "maker",
        "checker",
        "decided_at",
        "created_at",
    )
    list_filter = ("status", "requested_date", "created_at")
    search_fields = ("entry__entry_no", "reason", "maker__username", "checker__username")


@admin.register(SanctionScreeningRecord)
class SanctionScreeningRecordAdmin(admin.ModelAdmin):
    list_display = ("user", "provider", "status", "score", "reference", "screened_by", "created_at")
    list_filter = ("provider", "status", "created_at")
    search_fields = ("user__username", "reference")


@admin.register(TransactionMonitoringAlert)
class TransactionMonitoringAlertAdmin(admin.ModelAdmin):
    list_display = (
        "alert_type",
        "severity",
        "status",
        "user",
        "merchant",
        "case",
        "assigned_to",
        "created_at",
    )
    list_filter = ("alert_type", "severity", "status", "created_at")
    search_fields = ("alert_type", "note", "user__username", "merchant__code", "case__case_no")


@admin.register(MerchantWebhookEvent)
class MerchantWebhookEventAdmin(admin.ModelAdmin):
    list_display = (
        "credential",
        "event_type",
        "nonce",
        "signature_valid",
        "replay_detected",
        "status",
        "response_code",
        "created_at",
    )
    list_filter = ("signature_valid", "replay_detected", "status", "created_at")
    search_fields = ("credential__merchant__code", "nonce", "event_type")


@admin.register(AccessReviewRecord)
class AccessReviewRecordAdmin(admin.ModelAdmin):
    list_display = ("review_no", "user", "issue_type", "status", "reviewer", "resolved_at", "created_at")
    list_filter = ("issue_type", "status", "created_at")
    search_fields = ("review_no", "user__username", "details")


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


@admin.register(CustomerCIF)
class CustomerCIFAdmin(admin.ModelAdmin):
    list_display = ("cif_no", "user", "legal_name", "mobile_no", "email", "status", "created_by", "updated_at")
    list_filter = ("status", "created_at")
    search_fields = ("cif_no", "legal_name", "mobile_no", "email", "user__username")

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return ("cif_no",)
        return ()


@admin.register(AnalyticsEvent)
class AnalyticsEventAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "source",
        "event_name",
        "user",
        "external_id",
        "sent_to_clevertap",
    )
    list_filter = ("source", "event_name", "sent_to_clevertap", "created_at")
    search_fields = ("event_name", "user__username", "external_id", "session_id")
    readonly_fields = (
        "source",
        "event_name",
        "user",
        "session_id",
        "external_id",
        "properties",
        "sent_to_clevertap",
        "clevertap_error",
        "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
