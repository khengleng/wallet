from decimal import Decimal

from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone
from dj_wallet.mixins import WalletMixin
from .rbac import user_has_any_role, user_is_checker

FLOW_B2B = "b2b"
FLOW_B2C = "b2c"
FLOW_C2B = "c2b"
FLOW_P2G = "p2g"
FLOW_G2P = "g2p"
FLOW_CHOICES = (
    (FLOW_B2B, "B2B"),
    (FLOW_B2C, "B2C"),
    (FLOW_C2B, "C2B"),
    (FLOW_P2G, "P2G"),
    (FLOW_G2P, "G2P"),
)

APPROVAL_WORKFLOW_TREASURY = "treasury_transfer"
APPROVAL_WORKFLOW_KYB = "merchant_kyb"
APPROVAL_WORKFLOW_REFUND = "dispute_refund"
APPROVAL_WORKFLOW_PAYOUT = "settlement_payout"
APPROVAL_WORKFLOW_BACKDATE = "journal_backdate"
APPROVAL_WORKFLOW_CHOICES = (
    (APPROVAL_WORKFLOW_TREASURY, "Treasury Transfer"),
    (APPROVAL_WORKFLOW_KYB, "Merchant KYB"),
    (APPROVAL_WORKFLOW_REFUND, "Dispute Refund"),
    (APPROVAL_WORKFLOW_PAYOUT, "Settlement Payout"),
    (APPROVAL_WORKFLOW_BACKDATE, "Journal Backdate"),
)


def default_service_transaction_prefixes() -> dict:
    return {
        "deposit": "DEP",
        "withdraw": "WDR",
        "transfer": "TRF",
        "fx_exchange": "FX",
        "wallet_adjustment": "ADJ",
        "refund": "RFD",
        "loyalty_accrual": "LAC",
        "loyalty_redemption": "LRD",
        "b2b": "B2B",
        "b2c": "B2C",
        "c2b": "C2B",
        "p2g": "P2G",
        "g2p": "G2P",
    }


def default_nav_visibility_rules() -> dict:
    return {}


def default_sensitive_data_roles() -> list[str]:
    return []


def default_sensitive_visibility_rules() -> dict:
    return {}


WALLET_TYPE_PERSONAL = "P"
WALLET_TYPE_BUSINESS = "B"
WALLET_TYPE_CUSTOMER = "C"
WALLET_TYPE_GOVERNMENT = "G"
WALLET_TYPE_CHOICES = (
    (WALLET_TYPE_PERSONAL, "Personal"),
    (WALLET_TYPE_BUSINESS, "Business"),
    (WALLET_TYPE_CUSTOMER, "Customer"),
    (WALLET_TYPE_GOVERNMENT, "Government"),
)

class User(WalletMixin, AbstractUser):
    wallet_type = models.CharField(
        max_length=1, choices=WALLET_TYPE_CHOICES, default=WALLET_TYPE_CUSTOMER
    )

    @property
    def role_names(self) -> list[str]:
        return list(self.groups.values_list("name", flat=True))

    def has_role(self, role_name: str) -> bool:
        return user_has_any_role(self, [role_name])

    def has_any_role(self, role_names: list[str] | tuple[str, ...]) -> bool:
        return user_has_any_role(self, role_names)


class OperationSetting(models.Model):
    singleton_key = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    organization_name = models.CharField(max_length=128, default="DJ Wallet")
    merchant_id_prefix = models.CharField(max_length=16, default="MCH")
    wallet_id_prefix = models.CharField(max_length=16, default="WAL")
    transaction_id_prefix = models.CharField(max_length=16, default="TXN")
    service_transaction_prefixes = models.JSONField(
        default=default_service_transaction_prefixes,
        blank=True,
    )
    cif_id_prefix = models.CharField(max_length=16, default="CIF")
    journal_entry_prefix = models.CharField(max_length=16, default="JE")
    case_no_prefix = models.CharField(max_length=16, default="CASE")
    settlement_no_prefix = models.CharField(max_length=16, default="SETTLE")
    payout_ref_prefix = models.CharField(max_length=16, default="PAYOUT")
    recon_no_prefix = models.CharField(max_length=16, default="RECON")
    chargeback_no_prefix = models.CharField(max_length=16, default="CB")
    access_review_no_prefix = models.CharField(max_length=16, default="AR")
    enabled_currencies = models.JSONField(
        default=list,
        blank=True,
        help_text="List of active currency codes on this platform. Leave empty to use SUPPORTED_CURRENCIES setting.",
    )
    nav_visibility_rules = models.JSONField(
        default=default_nav_visibility_rules,
        blank=True,
        help_text=(
            "Optional menu visibility overrides. "
            "Format: {\"menu_key\": [\"role1\", \"role2\"]}. "
            "Leave empty to use secure defaults."
        ),
    )
    sensitive_data_roles = models.JSONField(
        default=default_sensitive_data_roles,
        blank=True,
        help_text=(
            "Roles allowed to view sensitive amounts/balances. "
            "Leave empty to use secure defaults."
        ),
    )
    sensitive_visibility_rules = models.JSONField(
        default=default_sensitive_visibility_rules,
        blank=True,
        help_text=(
            "Optional sensitive-data visibility overrides by domain. "
            "Format: {\"domain_key\": [\"role1\", \"role2\"]}."
        ),
    )
    updated_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="updated_operation_settings",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "System setting"
        verbose_name_plural = "System settings"

    def save(self, *args, **kwargs):
        self.singleton_key = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_solo(cls) -> "OperationSetting":
        obj, _created = cls.objects.get_or_create(singleton_key=1)
        return obj

    def __str__(self):
        return f"{self.organization_name} system setting"


class ApprovalRequest(models.Model):
    ACTION_DEPOSIT = "deposit"
    ACTION_WITHDRAW = "withdraw"
    ACTION_TRANSFER = "transfer"
    ACTION_CHOICES = (
        (ACTION_DEPOSIT, "Deposit"),
        (ACTION_WITHDRAW, "Withdraw"),
        (ACTION_TRANSFER, "Transfer"),
    )

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
        (STATUS_FAILED, "Failed"),
    )

    maker = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="made_approval_requests"
    )
    checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_approval_requests",
    )
    source_user = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="source_approval_requests"
    )
    recipient_user = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="recipient_approval_requests",
    )
    action = models.CharField(max_length=16, choices=ACTION_CHOICES)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True
    )
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    currency = models.CharField(max_length=12, default="USD")
    description = models.CharField(max_length=255, blank=True, default="")
    maker_note = models.TextField(blank=True, default="")
    checker_note = models.TextField(blank=True, default="")
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.action}:{self.amount} ({self.status})"

    def clean(self):
        if self.amount <= Decimal("0"):
            raise ValidationError("Amount must be greater than 0.")
        if not self.currency:
            raise ValidationError("Currency is required.")
        if self.action == self.ACTION_TRANSFER and not self.recipient_user:
            raise ValidationError("Transfer request requires a recipient.")
        if self.action != self.ACTION_TRANSFER and self.recipient_user:
            raise ValidationError("Only transfer request can set recipient.")

    def approve(self, checker: User, checker_note: str = ""):
        if self.status != self.STATUS_PENDING:
            raise ValidationError("Only pending request can be approved.")
        if not user_is_checker(checker):
            raise ValidationError("Only checker role can approve requests.")
        if checker.pk == self.maker_id:
            raise ValidationError("Maker and checker must be different users.")
        if self.required_checker_role and not user_has_any_role(checker, [self.required_checker_role]):
            raise ValidationError(
                f"Checker must have role {self.required_checker_role} for this treasury request."
            )

        description = self.description or "Approval workflow transaction"
        meta = {
            "approval_request_id": self.pk,
            "maker": self.maker.username,
            "checker": checker.username,
            "description": description,
            "currency": self.currency,
        }
        from dj_wallet.utils import get_wallet_service

        wallet_service = get_wallet_service()
        base_currency = getattr(settings, "PLATFORM_BASE_CURRENCY", "USD").upper()
        source_slug = "default" if self.currency.upper() == base_currency else self.currency.lower()
        source_wallet = self.source_user.get_wallet(source_slug)
        source_meta = source_wallet.meta if isinstance(source_wallet.meta, dict) else {}
        if source_meta.get("currency") != self.currency:
            source_meta["currency"] = self.currency
            source_wallet.meta = source_meta
            source_wallet.save(update_fields=["meta"])
        try:
            with transaction.atomic():
                if self.action == self.ACTION_DEPOSIT:
                    wallet_service.deposit(source_wallet, self.amount, meta=meta)
                elif self.action == self.ACTION_WITHDRAW:
                    wallet_service.withdraw(source_wallet, self.amount, meta=meta)
                elif self.action == self.ACTION_TRANSFER:
                    if self.recipient_user is None:
                        raise ValidationError("Recipient is required for transfer.")
                    recipient_slug = "default" if self.currency.upper() == base_currency else self.currency.lower()
                    recipient_wallet = self.recipient_user.get_wallet(recipient_slug)
                    recipient_meta = (
                        recipient_wallet.meta
                        if isinstance(recipient_wallet.meta, dict)
                        else {}
                    )
                    if recipient_meta.get("currency") != self.currency:
                        recipient_meta["currency"] = self.currency
                        recipient_wallet.meta = recipient_meta
                        recipient_wallet.save(update_fields=["meta"])
                    wallet_service.withdraw(source_wallet, self.amount, meta=meta)
                    wallet_service.deposit(recipient_wallet, self.amount, meta=meta)
                else:
                    raise ValidationError("Unsupported action.")

                self.status = self.STATUS_APPROVED
                self.checker = checker
                self.checker_note = checker_note
                self.decided_at = timezone.now()
                self.error_message = ""
                self.save(
                    update_fields=[
                        "status",
                        "checker",
                        "checker_note",
                        "decided_at",
                        "error_message",
                    ]
                )
        except Exception as exc:
            self.status = self.STATUS_FAILED
            self.checker = checker
            self.checker_note = checker_note
            self.decided_at = timezone.now()
            self.error_message = str(exc)
            self.save(
                update_fields=[
                    "status",
                    "checker",
                    "checker_note",
                    "decided_at",
                    "error_message",
                ]
            )
            raise

    def reject(self, checker: User, checker_note: str = ""):
        if self.status != self.STATUS_PENDING:
            raise ValidationError("Only pending request can be rejected.")
        if not user_is_checker(checker):
            raise ValidationError("Only checker role can reject requests.")
        if checker.pk == self.maker_id:
            raise ValidationError("Maker and checker must be different users.")

        self.status = self.STATUS_REJECTED
        self.checker = checker
        self.checker_note = checker_note
        self.decided_at = timezone.now()
        self.save(update_fields=["status", "checker", "checker_note", "decided_at"])


class TreasuryAccount(models.Model):
    name = models.CharField(max_length=64, unique=True)
    currency = models.CharField(max_length=12, default="USD")
    balance = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return f"{self.name} ({self.currency})"


class TreasuryPolicy(models.Model):
    singleton_key = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    single_txn_limit = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("100000"))
    daily_outflow_limit = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("1000000"))
    require_super_admin_above = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("500000"))
    currency = models.CharField(max_length=12, default="USD")
    updated_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="updated_treasury_policies",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Treasury policy"
        verbose_name_plural = "Treasury policies"

    def save(self, *args, **kwargs):
        self.singleton_key = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_solo(cls) -> "TreasuryPolicy":
        obj, _created = cls.objects.get_or_create(singleton_key=1)
        return obj

    def __str__(self):
        return f"Treasury policy ({self.currency})"


class TreasuryTransferRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
        (STATUS_FAILED, "Failed"),
    )

    maker = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="made_treasury_requests"
    )
    checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_treasury_requests",
    )
    from_account = models.ForeignKey(
        TreasuryAccount, on_delete=models.PROTECT, related_name="outgoing_requests"
    )
    to_account = models.ForeignKey(
        TreasuryAccount, on_delete=models.PROTECT, related_name="incoming_requests"
    )
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True
    )
    reason = models.CharField(max_length=255, blank=True, default="")
    required_checker_role = models.CharField(max_length=32, blank=True, default="")
    maker_note = models.TextField(blank=True, default="")
    checker_note = models.TextField(blank=True, default="")
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.from_account}->{self.to_account}:{self.amount} ({self.status})"

    def clean(self):
        if self.amount <= Decimal("0"):
            raise ValidationError("Amount must be greater than 0.")
        if self.from_account_id == self.to_account_id:
            raise ValidationError("From and To treasury accounts must be different.")
        if self.from_account.currency != self.to_account.currency:
            raise ValidationError("Cross-currency treasury transfer is not supported.")

    def approve(self, checker: User, checker_note: str = ""):
        if self.status != self.STATUS_PENDING:
            raise ValidationError("Only pending request can be approved.")
        if not user_is_checker(checker):
            raise ValidationError("Only checker role can approve requests.")
        if checker.pk == self.maker_id:
            raise ValidationError("Maker and checker must be different users.")

        try:
            with transaction.atomic():
                from_locked = TreasuryAccount.objects.select_for_update().get(
                    id=self.from_account_id
                )
                to_locked = TreasuryAccount.objects.select_for_update().get(
                    id=self.to_account_id
                )
                if from_locked.balance < self.amount:
                    raise ValidationError("Insufficient treasury balance.")

                from_locked.balance -= self.amount
                to_locked.balance += self.amount
                from_locked.save(update_fields=["balance", "updated_at"])
                to_locked.save(update_fields=["balance", "updated_at"])

                self.status = self.STATUS_APPROVED
                self.checker = checker
                self.checker_note = checker_note
                self.error_message = ""
                self.decided_at = timezone.now()
                self.save(
                    update_fields=[
                        "status",
                        "checker",
                        "checker_note",
                        "error_message",
                        "decided_at",
                    ]
                )
        except Exception as exc:
            self.status = self.STATUS_FAILED
            self.checker = checker
            self.checker_note = checker_note
            self.error_message = str(exc)
            self.decided_at = timezone.now()
            self.save(
                update_fields=[
                    "status",
                    "checker",
                    "checker_note",
                    "error_message",
                    "decided_at",
                ]
            )
            raise

    def reject(self, checker: User, checker_note: str = ""):
        if self.status != self.STATUS_PENDING:
            raise ValidationError("Only pending request can be rejected.")
        if not user_is_checker(checker):
            raise ValidationError("Only checker role can reject requests.")
        if checker.pk == self.maker_id:
            raise ValidationError("Maker and checker must be different users.")

        self.status = self.STATUS_REJECTED
        self.checker = checker
        self.checker_note = checker_note
        self.decided_at = timezone.now()
        self.save(update_fields=["status", "checker", "checker_note", "decided_at"])


class ChartOfAccount(models.Model):
    TYPE_ASSET = "asset"
    TYPE_LIABILITY = "liability"
    TYPE_EQUITY = "equity"
    TYPE_REVENUE = "revenue"
    TYPE_EXPENSE = "expense"
    ACCOUNT_TYPE_CHOICES = (
        (TYPE_ASSET, "Asset"),
        (TYPE_LIABILITY, "Liability"),
        (TYPE_EQUITY, "Equity"),
        (TYPE_REVENUE, "Revenue"),
        (TYPE_EXPENSE, "Expense"),
    )

    code = models.CharField(max_length=24, unique=True)
    name = models.CharField(max_length=128)
    account_type = models.CharField(max_length=16, choices=ACCOUNT_TYPE_CHOICES)
    currency = models.CharField(max_length=12, default="USD")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("code",)

    def __str__(self):
        return f"{self.code} - {self.name}"


class JournalEntry(models.Model):
    STATUS_DRAFT = "draft"
    STATUS_POSTED = "posted"
    STATUS_CHOICES = (
        (STATUS_DRAFT, "Draft"),
        (STATUS_POSTED, "Posted"),
    )

    entry_no = models.CharField(max_length=40, unique=True)
    reference = models.CharField(max_length=128, blank=True, default="")
    description = models.CharField(max_length=255, blank=True, default="")
    currency = models.CharField(max_length=12, default="USD")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_journal_entries"
    )
    posted_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="posted_journal_entries",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    posted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.entry_no} ({self.status})"

    @property
    def total_debit(self) -> Decimal:
        return sum((line.debit for line in self.lines.all()), Decimal("0"))

    @property
    def total_credit(self) -> Decimal:
        return sum((line.credit for line in self.lines.all()), Decimal("0"))

    def is_balanced(self) -> bool:
        return self.total_debit == self.total_credit and self.total_debit > Decimal("0")

    def post(self, actor: User):
        if self.status != self.STATUS_DRAFT:
            raise ValidationError("Only draft journal entries can be posted.")
        if not self.lines.exists():
            raise ValidationError("Cannot post empty journal entry.")
        if not self.is_balanced():
            raise ValidationError("Journal entry is not balanced.")
        if self.lines.exclude(account__currency=self.currency).exists():
            raise ValidationError("All journal lines must match entry currency.")
        entry_date = self.created_at.date()
        closed_period_exists = AccountingPeriodClose.objects.filter(
            currency=self.currency,
            is_closed=True,
            period_start__lte=entry_date,
            period_end__gte=entry_date,
        ).exists()
        if closed_period_exists:
            raise ValidationError("Accounting period is closed for this entry date.")
        if entry_date < timezone.localdate():
            approval = JournalBackdateApproval.objects.filter(
                entry=self,
                status=JournalBackdateApproval.STATUS_APPROVED,
            ).first()
            if approval is None:
                raise ValidationError("Backdated entries require approved backdate approval.")

        self.status = self.STATUS_POSTED
        self.posted_by = actor
        self.posted_at = timezone.now()
        self.save(update_fields=["status", "posted_by", "posted_at"])


class JournalLine(models.Model):
    entry = models.ForeignKey(
        JournalEntry, on_delete=models.CASCADE, related_name="lines"
    )
    account = models.ForeignKey(
        ChartOfAccount, on_delete=models.PROTECT, related_name="journal_lines"
    )
    debit = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    credit = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    memo = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("id",)

    def clean(self):
        if self.debit < Decimal("0") or self.credit < Decimal("0"):
            raise ValidationError("Debit/Credit cannot be negative.")
        if self.debit > Decimal("0") and self.credit > Decimal("0"):
            raise ValidationError("Line cannot have both debit and credit.")
        if self.debit == Decimal("0") and self.credit == Decimal("0"):
            raise ValidationError("Line must contain debit or credit amount.")

    def __str__(self):
        side = "DR" if self.debit > Decimal("0") else "CR"
        amount = self.debit if self.debit > Decimal("0") else self.credit
        return f"{self.entry.entry_no} {self.account.code} {side} {amount}"


class BackofficeAuditLog(models.Model):
    actor = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="backoffice_audit_logs"
    )
    action = models.CharField(max_length=128, db_index=True)
    target_type = models.CharField(max_length=64, blank=True, default="")
    target_id = models.CharField(max_length=64, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True, default="")
    metadata_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.action} by {self.actor.username} at {self.created_at.isoformat()}"

    def delete(self, *args, **kwargs):
        raise ValidationError("BackofficeAuditLog is immutable and cannot be deleted.")


class LoginLockout(models.Model):
    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField()
    failed_attempts = models.PositiveIntegerField(default=0)
    first_failed_at = models.DateTimeField(default=timezone.now)
    lock_until = models.DateTimeField(null=True, blank=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("username", "ip_address"),)
        ordering = ("-updated_at",)

    def is_locked(self) -> bool:
        return self.lock_until is not None and self.lock_until > timezone.now()

    def __str__(self):
        return f"{self.username}@{self.ip_address} ({self.failed_attempts})"


class FxRate(models.Model):
    base_currency = models.CharField(max_length=12)
    quote_currency = models.CharField(max_length=12)
    rate = models.DecimalField(max_digits=20, decimal_places=8)
    effective_at = models.DateTimeField(default=timezone.now, db_index=True)
    is_active = models.BooleanField(default=True)
    source_provider = models.CharField(max_length=64, blank=True, default="")
    source_reference = models.CharField(max_length=255, blank=True, default="")
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="created_fx_rates",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-effective_at", "-id")
        indexes = [
            models.Index(
                fields=["base_currency", "quote_currency", "effective_at"],
                name="fx_pair_effective_idx",
            )
        ]

    def clean(self):
        if self.base_currency == self.quote_currency:
            raise ValidationError("Base and quote currencies must be different.")
        if self.rate <= Decimal("0"):
            raise ValidationError("FX rate must be greater than 0.")

    def __str__(self):
        return f"{self.base_currency}/{self.quote_currency}={self.rate}"

    @classmethod
    def _cache_key(cls, base_currency: str, quote_currency: str) -> str:
        return f"fx_rate:v1:{base_currency.upper()}:{quote_currency.upper()}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        cache.delete(self._cache_key(self.base_currency, self.quote_currency))

    def delete(self, *args, **kwargs):
        cache.delete(self._cache_key(self.base_currency, self.quote_currency))
        return super().delete(*args, **kwargs)

    @classmethod
    def latest_rate(cls, base_currency: str, quote_currency: str):
        base = base_currency.upper()
        quote = quote_currency.upper()
        key = cls._cache_key(base, quote)
        cached = cache.get(key)
        if isinstance(cached, dict):
            try:
                obj = cls(
                    base_currency=base,
                    quote_currency=quote,
                    rate=Decimal(str(cached["rate"])),
                    is_active=True,
                    source_provider=cached.get("source_provider", ""),
                    source_reference=cached.get("source_reference", ""),
                )
                obj.id = cached.get("id")
                effective_at = cached.get("effective_at")
                if effective_at:
                    from datetime import datetime

                    obj.effective_at = datetime.fromisoformat(effective_at)
                return obj
            except Exception:
                cache.delete(key)

        latest = (
            cls.objects.filter(
                base_currency=base,
                quote_currency=quote,
                is_active=True,
            )
            .order_by("-effective_at", "-id")
            .first()
        )
        if latest is not None:
            ttl = int(getattr(settings, "FX_RATE_CACHE_TTL_SECONDS", 60))
            cache.set(
                key,
                {
                    "id": latest.id,
                    "rate": str(latest.rate),
                    "effective_at": latest.effective_at.isoformat()
                    if latest.effective_at
                    else "",
                    "source_provider": latest.source_provider,
                    "source_reference": latest.source_reference,
                },
                timeout=ttl,
            )
        return latest


class ServiceClassPolicy(models.Model):
    ENTITY_CUSTOMER = "customer"
    ENTITY_MERCHANT = "merchant"
    ENTITY_CHOICES = (
        (ENTITY_CUSTOMER, "Customer"),
        (ENTITY_MERCHANT, "Merchant"),
    )

    entity_type = models.CharField(max_length=16, choices=ENTITY_CHOICES)
    code = models.CharField(max_length=8)
    name = models.CharField(max_length=64)
    description = models.CharField(max_length=255, blank=True, default="")
    is_active = models.BooleanField(default=True)

    allow_deposit = models.BooleanField(default=True)
    allow_withdraw = models.BooleanField(default=True)
    allow_transfer = models.BooleanField(default=True)
    allow_fx = models.BooleanField(default=True)

    allow_b2b = models.BooleanField(default=True)
    allow_b2c = models.BooleanField(default=True)
    allow_c2b = models.BooleanField(default=True)
    allow_p2g = models.BooleanField(default=True)
    allow_g2p = models.BooleanField(default=True)

    single_txn_limit = models.DecimalField(
        max_digits=20, decimal_places=2, null=True, blank=True
    )
    daily_txn_count_limit = models.PositiveIntegerField(null=True, blank=True)
    daily_amount_limit = models.DecimalField(
        max_digits=20, decimal_places=2, null=True, blank=True
    )
    monthly_txn_count_limit = models.PositiveIntegerField(null=True, blank=True)
    monthly_amount_limit = models.DecimalField(
        max_digits=20, decimal_places=2, null=True, blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("entity_type", "code")
        constraints = [
            models.UniqueConstraint(
                fields=("entity_type", "code"),
                name="uniq_service_class_policy_entity_code",
            )
        ]

    def save(self, *args, **kwargs):
        self.code = (self.code or "").strip().upper()
        super().save(*args, **kwargs)

    def clean(self):
        if self.single_txn_limit is not None and self.single_txn_limit <= Decimal("0"):
            raise ValidationError("Single transaction limit must be greater than 0.")
        if self.daily_amount_limit is not None and self.daily_amount_limit <= Decimal("0"):
            raise ValidationError("Daily amount limit must be greater than 0.")
        if self.monthly_amount_limit is not None and self.monthly_amount_limit <= Decimal("0"):
            raise ValidationError("Monthly amount limit must be greater than 0.")
        if self.daily_txn_count_limit is not None and self.daily_txn_count_limit <= 0:
            raise ValidationError("Daily transaction count limit must be greater than 0.")
        if self.monthly_txn_count_limit is not None and self.monthly_txn_count_limit <= 0:
            raise ValidationError("Monthly transaction count limit must be greater than 0.")

    def allows_wallet_action(self, action: str) -> bool:
        return {
            "deposit": self.allow_deposit,
            "withdraw": self.allow_withdraw,
            "transfer": self.allow_transfer,
            "fx": self.allow_fx,
        }.get((action or "").strip().lower(), True)

    def allows_flow(self, flow_type: str) -> bool:
        return {
            FLOW_B2B: self.allow_b2b,
            FLOW_B2C: self.allow_b2c,
            FLOW_C2B: self.allow_c2b,
            FLOW_P2G: self.allow_p2g,
            FLOW_G2P: self.allow_g2p,
        }.get((flow_type or "").strip().lower(), True)

    def __str__(self):
        return f"{self.entity_type}:{self.code} - {self.name}"


class TariffRule(models.Model):
    ENTITY_ANY = "any"
    ENTITY_CUSTOMER = ServiceClassPolicy.ENTITY_CUSTOMER
    ENTITY_MERCHANT = ServiceClassPolicy.ENTITY_MERCHANT
    ENTITY_CHOICES = (
        (ENTITY_ANY, "Any"),
        (ENTITY_CUSTOMER, "Customer"),
        (ENTITY_MERCHANT, "Merchant"),
    )

    CHARGE_SIDE_PAYER = "payer"
    CHARGE_SIDE_PAYEE = "payee"
    CHARGE_SIDE_CHOICES = (
        (CHARGE_SIDE_PAYER, "Charge Payer"),
        (CHARGE_SIDE_PAYEE, "Charge Payee"),
    )

    FEE_MODE_FLAT = "flat"
    FEE_MODE_BPS = "bps"
    FEE_MODE_CHOICES = (
        (FEE_MODE_FLAT, "Flat Amount"),
        (FEE_MODE_BPS, "Percent (BPS)"),
    )

    transaction_type = models.CharField(max_length=32, db_index=True)
    name = models.CharField(max_length=96)
    description = models.CharField(max_length=255, blank=True, default="")
    is_active = models.BooleanField(default=True, db_index=True)
    priority = models.PositiveIntegerField(
        default=100,
        help_text="Lower value = higher priority.",
    )

    payer_entity_type = models.CharField(
        max_length=16,
        choices=ENTITY_CHOICES,
        default=ENTITY_ANY,
    )
    payee_entity_type = models.CharField(
        max_length=16,
        choices=ENTITY_CHOICES,
        default=ENTITY_ANY,
    )
    payer_service_class = models.ForeignKey(
        ServiceClassPolicy,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="payer_tariff_rules",
    )
    payee_service_class = models.ForeignKey(
        ServiceClassPolicy,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="payee_tariff_rules",
    )

    currency = models.CharField(
        max_length=12,
        blank=True,
        default="",
        help_text="Leave empty to apply to any currency.",
    )
    min_amount = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    max_amount = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)

    charge_side = models.CharField(
        max_length=8,
        choices=CHARGE_SIDE_CHOICES,
        default=CHARGE_SIDE_PAYER,
    )
    fee_mode = models.CharField(
        max_length=8,
        choices=FEE_MODE_CHOICES,
        default=FEE_MODE_FLAT,
    )
    fee_value = models.DecimalField(max_digits=20, decimal_places=6, default=Decimal("0"))
    minimum_fee = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    maximum_fee = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("priority", "id")

    def clean(self):
        if self.fee_value < Decimal("0"):
            raise ValidationError("Fee value cannot be negative.")
        if self.min_amount is not None and self.min_amount <= Decimal("0"):
            raise ValidationError("Minimum amount must be greater than 0.")
        if self.max_amount is not None and self.max_amount <= Decimal("0"):
            raise ValidationError("Maximum amount must be greater than 0.")
        if (
            self.min_amount is not None
            and self.max_amount is not None
            and self.max_amount < self.min_amount
        ):
            raise ValidationError("Maximum amount must be greater than minimum amount.")
        if self.minimum_fee is not None and self.minimum_fee < Decimal("0"):
            raise ValidationError("Minimum fee cannot be negative.")
        if self.maximum_fee is not None and self.maximum_fee < Decimal("0"):
            raise ValidationError("Maximum fee cannot be negative.")
        if (
            self.minimum_fee is not None
            and self.maximum_fee is not None
            and self.maximum_fee < self.minimum_fee
        ):
            raise ValidationError("Maximum fee must be greater than minimum fee.")
        if self.payer_service_class and self.payer_service_class.entity_type != self.payer_entity_type:
            raise ValidationError("Payer service class entity type does not match payer entity type.")
        if self.payee_service_class and self.payee_service_class.entity_type != self.payee_entity_type:
            raise ValidationError("Payee service class entity type does not match payee entity type.")
        if self.fee_mode == self.FEE_MODE_BPS and self.fee_value > Decimal("10000"):
            raise ValidationError("BPS fee cannot exceed 10000.")

    def __str__(self):
        return f"{self.transaction_type}:{self.name}"


class Merchant(WalletMixin, models.Model):
    STATUS_ACTIVE = "active"
    STATUS_SUSPENDED = "suspended"
    STATUS_INACTIVE = "inactive"
    STATUS_CHOICES = (
        (STATUS_ACTIVE, "Active"),
        (STATUS_SUSPENDED, "Suspended"),
        (STATUS_INACTIVE, "Inactive"),
    )

    code = models.CharField(max_length=40, unique=True)
    name = models.CharField(max_length=128)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    settlement_currency = models.CharField(max_length=12, default="USD")
    wallet_type = models.CharField(
        max_length=1,
        choices=(
            (WALLET_TYPE_BUSINESS, "Business"),
            (WALLET_TYPE_GOVERNMENT, "Government"),
        ),
        default=WALLET_TYPE_BUSINESS,
    )
    is_government = models.BooleanField(default=False)
    contact_email = models.EmailField(blank=True, default="")
    contact_phone = models.CharField(max_length=40, blank=True, default="")
    owner = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="managed_merchants",
    )
    service_class = models.ForeignKey(
        ServiceClassPolicy,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="merchants",
        limit_choices_to={"entity_type": ServiceClassPolicy.ENTITY_MERCHANT},
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="created_merchants",
    )
    updated_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="updated_merchants",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("code",)

    def __str__(self):
        return f"{self.code} - {self.name}"


class MerchantLoyaltyProgram(models.Model):
    merchant = models.OneToOneField(
        Merchant, on_delete=models.CASCADE, related_name="loyalty_program"
    )
    is_enabled = models.BooleanField(default=True)
    earn_rate = models.DecimalField(
        max_digits=12,
        decimal_places=4,
        default=Decimal("1.0000"),
        help_text="Points earned for each 1 unit of settlement currency spent.",
    )
    redeem_rate = models.DecimalField(
        max_digits=12,
        decimal_places=4,
        default=Decimal("1.0000"),
        help_text="Currency value deducted for each 1 point redeemed.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("merchant__code",)

    def clean(self):
        if self.earn_rate <= Decimal("0"):
            raise ValidationError("Earn rate must be greater than 0.")
        if self.redeem_rate <= Decimal("0"):
            raise ValidationError("Redeem rate must be greater than 0.")

    def __str__(self):
        return f"{self.merchant.code} loyalty"


class MerchantWalletCapability(models.Model):
    merchant = models.OneToOneField(
        Merchant, on_delete=models.CASCADE, related_name="wallet_capability"
    )
    supports_b2b = models.BooleanField(default=True)
    supports_b2c = models.BooleanField(default=True)
    supports_c2b = models.BooleanField(default=True)
    supports_p2g = models.BooleanField(default=False)
    supports_g2p = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Merchant wallet capabilities"
        ordering = ("merchant__code",)

    def supports_flow(self, flow_type: str) -> bool:
        return {
            FLOW_B2B: self.supports_b2b,
            FLOW_B2C: self.supports_b2c,
            FLOW_C2B: self.supports_c2b,
            FLOW_P2G: self.supports_p2g,
            FLOW_G2P: self.supports_g2p,
        }.get(flow_type, False)

    def __str__(self):
        return f"{self.merchant.code} capability"


class MerchantLoyaltyEvent(models.Model):
    TYPE_ACCRUAL = "accrual"
    TYPE_REDEMPTION = "redemption"
    TYPE_CHOICES = (
        (TYPE_ACCRUAL, "Accrual"),
        (TYPE_REDEMPTION, "Redemption"),
    )

    merchant = models.ForeignKey(
        Merchant, on_delete=models.PROTECT, related_name="loyalty_events"
    )
    customer = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="loyalty_events"
    )
    event_type = models.CharField(max_length=16, choices=TYPE_CHOICES)
    flow_type = models.CharField(max_length=8, choices=FLOW_CHOICES, default=FLOW_B2C)
    points = models.DecimalField(max_digits=20, decimal_places=2)
    amount = models.DecimalField(
        max_digits=20,
        decimal_places=2,
        default=Decimal("0"),
        help_text="Settlement currency amount tied to the event.",
    )
    currency = models.CharField(max_length=12, default="USD")
    reference = models.CharField(max_length=128, blank=True, default="")
    note = models.CharField(max_length=255, blank=True, default="")
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="created_loyalty_events",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def clean(self):
        if self.points <= Decimal("0"):
            raise ValidationError("Points must be greater than 0.")
        if self.amount < Decimal("0"):
            raise ValidationError("Amount cannot be negative.")

    def __str__(self):
        return (
            f"{self.merchant.code}:{self.customer.username}:{self.event_type}:{self.points}"
        )


class MerchantCashflowEvent(models.Model):
    merchant = models.ForeignKey(
        Merchant, on_delete=models.PROTECT, related_name="cashflow_events"
    )
    flow_type = models.CharField(max_length=8, choices=FLOW_CHOICES)
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    fee_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    net_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    currency = models.CharField(max_length=12, default="USD")
    from_user = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="merchant_cashflow_outgoing",
    )
    to_user = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="merchant_cashflow_incoming",
    )
    counterparty_merchant = models.ForeignKey(
        Merchant,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="counterparty_cashflow_events",
    )
    reference = models.CharField(max_length=128, blank=True, default="")
    settlement_reference = models.CharField(max_length=48, blank=True, default="", db_index=True)
    settled_at = models.DateTimeField(null=True, blank=True, db_index=True)
    note = models.CharField(max_length=255, blank=True, default="")
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="created_cashflow_events",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def clean(self):
        if self.amount <= Decimal("0"):
            raise ValidationError("Amount must be greater than 0.")
        if self.fee_amount < Decimal("0"):
            raise ValidationError("Fee amount cannot be negative.")
        if self.net_amount < Decimal("0"):
            raise ValidationError("Net amount cannot be negative.")
        if not self.currency:
            raise ValidationError("Currency is required.")

    def __str__(self):
        return f"{self.merchant.code}:{self.flow_type}:{self.amount}{self.currency}"


class MerchantKYBRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    )

    merchant = models.ForeignKey(
        Merchant, on_delete=models.PROTECT, related_name="kyb_requests"
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    legal_name = models.CharField(max_length=128)
    registration_number = models.CharField(max_length=64, blank=True, default="")
    tax_id = models.CharField(max_length=64, blank=True, default="")
    country_code = models.CharField(max_length=3, blank=True, default="")
    documents_json = models.JSONField(default=dict, blank=True)
    risk_note = models.CharField(max_length=255, blank=True, default="")
    maker = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_kyb_requests"
    )
    checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_kyb_requests",
    )
    checker_note = models.CharField(max_length=255, blank=True, default="")
    decided_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.merchant.code}:KYB:{self.status}"


class MerchantFeeRule(models.Model):
    merchant = models.ForeignKey(
        Merchant, on_delete=models.CASCADE, related_name="fee_rules"
    )
    flow_type = models.CharField(max_length=8, choices=FLOW_CHOICES)
    percent_bps = models.PositiveIntegerField(default=0, help_text="Fee percentage in basis points.")
    fixed_fee = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    minimum_fee = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    maximum_fee = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_merchant_fee_rules"
    )
    updated_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="updated_merchant_fee_rules"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("merchant__code", "flow_type")
        unique_together = ("merchant", "flow_type")

    def clean(self):
        if self.maximum_fee < Decimal("0") or self.minimum_fee < Decimal("0") or self.fixed_fee < Decimal("0"):
            raise ValidationError("Fee values cannot be negative.")
        if self.maximum_fee and self.minimum_fee and self.maximum_fee < self.minimum_fee:
            raise ValidationError("Maximum fee cannot be less than minimum fee.")

    def __str__(self):
        return f"{self.merchant.code}:{self.flow_type}:bps={self.percent_bps}"


class MerchantRiskProfile(models.Model):
    merchant = models.OneToOneField(
        Merchant, on_delete=models.CASCADE, related_name="risk_profile"
    )
    daily_txn_limit = models.PositiveIntegerField(default=5000)
    daily_amount_limit = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("1000000"))
    single_txn_limit = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("50000"))
    reserve_ratio_bps = models.PositiveIntegerField(default=0)
    require_manual_review_above = models.DecimalField(
        max_digits=20, decimal_places=2, default=Decimal("0")
    )
    is_high_risk = models.BooleanField(default=False)
    updated_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="updated_merchant_risk_profiles"
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("merchant__code",)

    def __str__(self):
        return f"{self.merchant.code}:risk"


class MerchantApiCredential(models.Model):
    merchant = models.OneToOneField(
        Merchant, on_delete=models.CASCADE, related_name="api_credential"
    )
    key_id = models.CharField(max_length=64, unique=True)
    secret_hash = models.CharField(max_length=128)
    scopes_csv = models.CharField(max_length=255, blank=True, default="wallet:read,payout:read,webhook:write")
    webhook_url = models.URLField(blank=True, default="")
    is_active = models.BooleanField(default=True)
    last_rotated_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_merchant_api_credentials"
    )
    updated_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="updated_merchant_api_credentials"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("merchant__code",)

    def __str__(self):
        return f"{self.merchant.code}:{self.key_id}"


class MerchantSettlementRecord(models.Model):
    STATUS_DRAFT = "draft"
    STATUS_POSTED = "posted"
    STATUS_PAID = "paid"
    STATUS_CHOICES = (
        (STATUS_DRAFT, "Draft"),
        (STATUS_POSTED, "Posted"),
        (STATUS_PAID, "Paid"),
    )

    merchant = models.ForeignKey(
        Merchant, on_delete=models.PROTECT, related_name="settlement_records"
    )
    settlement_no = models.CharField(max_length=40, unique=True)
    currency = models.CharField(max_length=12, default="USD")
    period_start = models.DateField()
    period_end = models.DateField()
    gross_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    fee_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    net_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    event_count = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=STATUS_DRAFT, db_index=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_merchant_settlements"
    )
    approved_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="approved_merchant_settlements",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.settlement_no}:{self.merchant.code}:{self.status}"


class DisputeRefundRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_EXECUTED = "executed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
        (STATUS_EXECUTED, "Executed"),
        (STATUS_FAILED, "Failed"),
    )

    case = models.ForeignKey(
        "OperationCase", on_delete=models.PROTECT, related_name="refund_requests"
    )
    merchant = models.ForeignKey(
        Merchant, on_delete=models.PROTECT, related_name="refund_requests"
    )
    customer = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="refund_requests"
    )
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    currency = models.CharField(max_length=12, default="USD")
    reason = models.CharField(max_length=255, blank=True, default="")
    maker = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="made_refund_requests"
    )
    checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_refund_requests",
    )
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True
    )
    maker_note = models.TextField(blank=True, default="")
    checker_note = models.TextField(blank=True, default="")
    source_cashflow_event = models.ForeignKey(
        MerchantCashflowEvent,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="refund_requests",
    )
    executed_event = models.ForeignKey(
        MerchantCashflowEvent,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="executed_refund_requests",
    )
    error_message = models.TextField(blank=True, default="")
    sla_due_at = models.DateTimeField(null=True, blank=True, db_index=True)
    escalated_at = models.DateTimeField(null=True, blank=True)
    escalation_reason = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def clean(self):
        if self.amount <= Decimal("0"):
            raise ValidationError("Refund amount must be greater than 0.")

    def __str__(self):
        return f"REFUND:{self.id}:{self.merchant.code}:{self.status}"


class SettlementPayout(models.Model):
    STATUS_PENDING = "pending"
    STATUS_SENT = "sent"
    STATUS_SETTLED = "settled"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_SENT, "Sent"),
        (STATUS_SETTLED, "Settled"),
        (STATUS_FAILED, "Failed"),
    )

    settlement = models.OneToOneField(
        MerchantSettlementRecord, on_delete=models.CASCADE, related_name="payout"
    )
    payout_reference = models.CharField(max_length=48, unique=True)
    payout_channel = models.CharField(max_length=32, default="bank_transfer")
    destination_account = models.CharField(max_length=128, blank=True, default="")
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    currency = models.CharField(max_length=12, default="USD")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    provider_response = models.JSONField(default=dict, blank=True)
    initiated_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="initiated_settlement_payouts"
    )
    approved_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="approved_settlement_payouts",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    settled_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.payout_reference}:{self.status}"


class SettlementBatchFile(models.Model):
    STATUS_DRAFT = "draft"
    STATUS_GENERATED = "generated"
    STATUS_APPROVED = "approved"
    STATUS_UPLOADED = "uploaded"
    STATUS_PROCESSED = "processed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_DRAFT, "Draft"),
        (STATUS_GENERATED, "Generated"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_UPLOADED, "Uploaded"),
        (STATUS_PROCESSED, "Processed"),
        (STATUS_FAILED, "Failed"),
    )

    batch_no = models.CharField(max_length=40, unique=True)
    currency = models.CharField(max_length=12, default="USD")
    period_start = models.DateField()
    period_end = models.DateField()
    settlement_count = models.PositiveIntegerField(default=0)
    payout_count = models.PositiveIntegerField(default=0)
    total_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_DRAFT, db_index=True)
    payload_json = models.JSONField(default=dict, blank=True)
    file = models.FileField(upload_to="settlement_batches/", null=True, blank=True)
    external_url = models.URLField(blank=True, default="")
    note = models.CharField(max_length=255, blank=True, default="")
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_settlement_batches"
    )
    approved_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="approved_settlement_batches",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.batch_no}:{self.status}"


class SettlementException(models.Model):
    STATUS_OPEN = "open"
    STATUS_IN_REVIEW = "in_review"
    STATUS_RESOLVED = "resolved"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_REVIEW, "In Review"),
        (STATUS_RESOLVED, "Resolved"),
    )

    settlement = models.ForeignKey(
        MerchantSettlementRecord,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="exceptions",
    )
    payout = models.ForeignKey(
        SettlementPayout,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="exceptions",
    )
    batch_file = models.ForeignKey(
        SettlementBatchFile,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="exceptions",
    )
    reason_code = models.CharField(max_length=64, default="unknown")
    severity = models.CharField(max_length=16, default="medium")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    detail = models.CharField(max_length=255, blank=True, default="")
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="assigned_settlement_exceptions",
    )
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="resolved_settlement_exceptions",
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="created_settlement_exceptions",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"SETTLE-EX-{self.id}:{self.status}"


class ReconciliationRun(models.Model):
    STATUS_DRAFT = "draft"
    STATUS_COMPLETED = "completed"
    STATUS_CHOICES = (
        (STATUS_DRAFT, "Draft"),
        (STATUS_COMPLETED, "Completed"),
    )

    source = models.CharField(max_length=64, default="internal_vs_settlement")
    run_no = models.CharField(max_length=40, unique=True)
    currency = models.CharField(max_length=12, default="USD")
    period_start = models.DateField()
    period_end = models.DateField()
    internal_count = models.PositiveIntegerField(default=0)
    internal_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    external_count = models.PositiveIntegerField(default=0)
    external_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    delta_count = models.IntegerField(default=0)
    delta_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_DRAFT, db_index=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_reconciliation_runs"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.run_no}:{self.status}"


class ReconciliationBreak(models.Model):
    STATUS_OPEN = "open"
    STATUS_IN_REVIEW = "in_review"
    STATUS_RESOLVED = "resolved"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_REVIEW, "In Review"),
        (STATUS_RESOLVED, "Resolved"),
    )
    CATEGORY_AMOUNT = "amount_mismatch"
    CATEGORY_COUNT = "count_mismatch"
    CATEGORY_MISSING_EXTERNAL = "missing_external"
    CATEGORY_MISSING_INTERNAL = "missing_internal"
    CATEGORY_DUPLICATE = "duplicate"
    CATEGORY_TIMING = "timing_cutoff"
    CATEGORY_REFERENCE = "reference_mismatch"
    CATEGORY_OTHER = "other"
    CATEGORY_CHOICES = (
        (CATEGORY_AMOUNT, "Amount mismatch"),
        (CATEGORY_COUNT, "Count mismatch"),
        (CATEGORY_MISSING_EXTERNAL, "Missing external"),
        (CATEGORY_MISSING_INTERNAL, "Missing internal"),
        (CATEGORY_DUPLICATE, "Duplicate"),
        (CATEGORY_TIMING, "Timing / cutoff"),
        (CATEGORY_REFERENCE, "Reference mismatch"),
        (CATEGORY_OTHER, "Other"),
    )
    MATCH_UNMATCHED = "unmatched"
    MATCH_MATCHED = "matched"
    MATCH_CHOICES = (
        (MATCH_UNMATCHED, "Unmatched"),
        (MATCH_MATCHED, "Matched"),
    )
    RESOLUTION_NONE = "none"
    RESOLUTION_PENDING = "pending"
    RESOLUTION_APPROVED = "approved"
    RESOLUTION_REJECTED = "rejected"
    RESOLUTION_CHOICES = (
        (RESOLUTION_NONE, "None"),
        (RESOLUTION_PENDING, "Pending"),
        (RESOLUTION_APPROVED, "Approved"),
        (RESOLUTION_REJECTED, "Rejected"),
    )

    run = models.ForeignKey(
        ReconciliationRun, on_delete=models.CASCADE, related_name="breaks"
    )
    merchant = models.ForeignKey(
        Merchant,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="reconciliation_breaks",
    )
    reference = models.CharField(max_length=128, blank=True, default="")
    issue_type = models.CharField(max_length=64, default="amount_mismatch")
    break_category = models.CharField(
        max_length=32,
        choices=CATEGORY_CHOICES,
        default=CATEGORY_AMOUNT,
    )
    match_status = models.CharField(
        max_length=16,
        choices=MATCH_CHOICES,
        default=MATCH_UNMATCHED,
        db_index=True,
    )
    internal_txn_ref = models.CharField(max_length=128, blank=True, default="")
    external_txn_ref = models.CharField(max_length=128, blank=True, default="")
    expected_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    actual_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    delta_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0"))
    note = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    resolution_status = models.CharField(
        max_length=16,
        choices=RESOLUTION_CHOICES,
        default=RESOLUTION_NONE,
        db_index=True,
    )
    resolution_requested_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="requested_reconciliation_break_resolutions",
    )
    resolution_requested_at = models.DateTimeField(null=True, blank=True)
    resolution_request_note = models.CharField(max_length=255, blank=True, default="")
    resolution_checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_reconciliation_break_resolutions",
    )
    resolution_checker_note = models.CharField(max_length=255, blank=True, default="")
    resolution_decided_at = models.DateTimeField(null=True, blank=True)
    required_checker_role = models.CharField(max_length=32, blank=True, default="risk")
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="assigned_reconciliation_breaks",
    )
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_reconciliation_breaks"
    )
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="resolved_reconciliation_breaks",
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.run.run_no}:{self.status}:{self.issue_type}"


class ReconciliationEvidence(models.Model):
    recon_break = models.ForeignKey(
        ReconciliationBreak, on_delete=models.CASCADE, related_name="evidences"
    )
    title = models.CharField(max_length=255)
    document_type = models.CharField(max_length=64, default="supporting_doc")
    file = models.FileField(upload_to="reconciliation_evidence/", null=True, blank=True)
    external_url = models.URLField(blank=True, default="")
    note = models.CharField(max_length=255, blank=True, default="")
    uploaded_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="uploaded_reconciliation_evidences"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def clean(self):
        if not self.file and not self.external_url:
            raise ValidationError("Either file or external URL is required.")

    def __str__(self):
        return f"{self.recon_break.id}:{self.title}"


class ChargebackCase(models.Model):
    STATUS_OPEN = "open"
    STATUS_REPRESENTED = "represented"
    STATUS_PRE_ARBITRATION = "pre_arbitration"
    STATUS_WON = "won"
    STATUS_LOST = "lost"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_REPRESENTED, "Represented"),
        (STATUS_PRE_ARBITRATION, "Pre-Arbitration"),
        (STATUS_WON, "Won"),
        (STATUS_LOST, "Lost"),
        (STATUS_CLOSED, "Closed"),
    )

    chargeback_no = models.CharField(max_length=40, unique=True)
    case = models.ForeignKey(
        "OperationCase", on_delete=models.PROTECT, related_name="chargebacks"
    )
    merchant = models.ForeignKey(
        Merchant, on_delete=models.PROTECT, related_name="chargebacks"
    )
    customer = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="chargebacks"
    )
    source_cashflow_event = models.ForeignKey(
        MerchantCashflowEvent,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="chargebacks",
    )
    reason_code = models.CharField(max_length=32, blank=True, default="")
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    currency = models.CharField(max_length=12, default="USD")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    network_reference = models.CharField(max_length=64, blank=True, default="")
    due_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_chargeback_cases"
    )
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="assigned_chargeback_cases",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.chargeback_no}:{self.status}"


class ChargebackEvidence(models.Model):
    chargeback = models.ForeignKey(
        ChargebackCase, on_delete=models.CASCADE, related_name="evidences"
    )
    document_type = models.CharField(max_length=64, default="receipt")
    document_url = models.URLField()
    note = models.CharField(max_length=255, blank=True, default="")
    uploaded_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="uploaded_chargeback_evidences"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.chargeback.chargeback_no}:{self.document_type}"


class ApprovalMatrixRule(models.Model):
    workflow_type = models.CharField(max_length=32, choices=APPROVAL_WORKFLOW_CHOICES, db_index=True)
    currency = models.CharField(max_length=12, blank=True, default="", help_text="Blank means all currencies")
    min_amount = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    max_amount = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    required_checker_role = models.CharField(max_length=64)
    is_active = models.BooleanField(default=True, db_index=True)
    description = models.CharField(max_length=255, blank=True, default="")
    updated_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="updated_approval_matrix_rules",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("workflow_type", "currency", "min_amount", "max_amount", "id")

    def clean(self):
        if self.min_amount is not None and self.min_amount < Decimal("0"):
            raise ValidationError("Minimum amount cannot be negative.")
        if self.max_amount is not None and self.max_amount < Decimal("0"):
            raise ValidationError("Maximum amount cannot be negative.")
        if (
            self.min_amount is not None
            and self.max_amount is not None
            and self.min_amount > self.max_amount
        ):
            raise ValidationError("Minimum amount cannot be greater than maximum amount.")

    def __str__(self):
        ccy = self.currency or "ANY"
        return f"{self.workflow_type}:{ccy}:{self.required_checker_role}"


class BusinessDocument(models.Model):
    SOURCE_GENERAL = "general"
    SOURCE_CASE = "case"
    SOURCE_KYB = "kyb"
    SOURCE_CHARGEBACK = "chargeback"
    SOURCE_REFUND = "refund"
    SOURCE_RECONCILIATION = "reconciliation"
    SOURCE_CHOICES = (
        (SOURCE_GENERAL, "General"),
        (SOURCE_CASE, "Case"),
        (SOURCE_KYB, "KYB"),
        (SOURCE_CHARGEBACK, "Chargeback"),
        (SOURCE_REFUND, "Refund"),
        (SOURCE_RECONCILIATION, "Reconciliation"),
    )

    source_module = models.CharField(max_length=32, choices=SOURCE_CHOICES, default=SOURCE_GENERAL, db_index=True)
    title = models.CharField(max_length=255)
    document_type = models.CharField(max_length=64, default="generic")
    file = models.FileField(upload_to="business_documents/", null=True, blank=True)
    external_url = models.URLField(blank=True, default="")
    is_internal = models.BooleanField(default=True)
    metadata_json = models.JSONField(default=dict, blank=True)
    case = models.ForeignKey(
        "OperationCase",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="documents",
    )
    merchant = models.ForeignKey(
        Merchant,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="documents",
    )
    customer = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="business_documents",
    )
    chargeback = models.ForeignKey(
        ChargebackCase,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="documents",
    )
    refund_request = models.ForeignKey(
        DisputeRefundRequest,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="documents",
    )
    kyb_request = models.ForeignKey(
        MerchantKYBRequest,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="documents",
    )
    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="uploaded_business_documents",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def clean(self):
        if not self.file and not self.external_url:
            raise ValidationError("Either file upload or external URL is required.")

    def __str__(self):
        return f"{self.source_module}:{self.title}"


class AccountingPeriodClose(models.Model):
    period_start = models.DateField()
    period_end = models.DateField()
    currency = models.CharField(max_length=12, default="USD")
    is_closed = models.BooleanField(default=False, db_index=True)
    closed_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="closed_accounting_periods",
    )
    closed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_accounting_periods"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-period_start", "-id")
        unique_together = ("period_start", "period_end", "currency")

    def __str__(self):
        return f"{self.period_start}:{self.period_end}:{self.currency}:{self.is_closed}"


class JournalBackdateApproval(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    )

    entry = models.OneToOneField(
        JournalEntry, on_delete=models.CASCADE, related_name="backdate_approval"
    )
    requested_date = models.DateField()
    reason = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    maker = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="made_backdate_approvals"
    )
    checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_backdate_approvals",
    )
    checker_note = models.CharField(max_length=255, blank=True, default="")
    decided_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.entry.entry_no}:{self.status}"


class JournalEntryApproval(models.Model):
    TYPE_POST = "post"
    TYPE_REVERSAL = "reversal"
    TYPE_RECLASS = "reclass"
    TYPE_CHOICES = (
        (TYPE_POST, "Post Draft Entry"),
        (TYPE_REVERSAL, "Reversal"),
        (TYPE_RECLASS, "Reclassification"),
    )

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    )

    entry = models.OneToOneField(
        JournalEntry,
        on_delete=models.CASCADE,
        related_name="approval_request",
    )
    request_type = models.CharField(max_length=16, choices=TYPE_CHOICES, default=TYPE_POST)
    source_entry = models.ForeignKey(
        JournalEntry,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="derived_approval_requests",
    )
    reason = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
    )
    maker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="made_journal_entry_approvals",
    )
    checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_journal_entry_approvals",
    )
    checker_note = models.CharField(max_length=255, blank=True, default="")
    decided_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def clean(self):
        if self.request_type in {self.TYPE_REVERSAL, self.TYPE_RECLASS} and not self.source_entry_id:
            raise ValidationError("Reversal/Reclass request must reference source entry.")

    def __str__(self):
        return f"{self.entry.entry_no}:{self.request_type}:{self.status}"


class SanctionScreeningRecord(models.Model):
    STATUS_CLEAR = "clear"
    STATUS_POTENTIAL_MATCH = "potential_match"
    STATUS_CONFIRMED_MATCH = "confirmed_match"
    STATUS_CHOICES = (
        (STATUS_CLEAR, "Clear"),
        (STATUS_POTENTIAL_MATCH, "Potential Match"),
        (STATUS_CONFIRMED_MATCH, "Confirmed Match"),
    )

    user = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="sanction_screenings"
    )
    provider = models.CharField(max_length=64, default="internal")
    reference = models.CharField(max_length=64, blank=True, default="")
    score = models.DecimalField(max_digits=8, decimal_places=4, default=Decimal("0"))
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_CLEAR, db_index=True)
    details_json = models.JSONField(default=dict, blank=True)
    screened_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="performed_sanction_screenings",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.user.username}:{self.status}:{self.provider}"


class TransactionMonitoringAlert(models.Model):
    STATUS_OPEN = "open"
    STATUS_IN_REVIEW = "in_review"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_REVIEW, "In Review"),
        (STATUS_CLOSED, "Closed"),
    )

    alert_type = models.CharField(max_length=64, default="velocity")
    severity = models.CharField(max_length=16, default="medium")
    user = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="monitoring_alerts",
    )
    merchant = models.ForeignKey(
        Merchant,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="monitoring_alerts",
    )
    cashflow_event = models.ForeignKey(
        MerchantCashflowEvent,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="monitoring_alerts",
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    note = models.CharField(max_length=255, blank=True, default="")
    case = models.ForeignKey(
        "OperationCase",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="monitoring_alerts",
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="created_monitoring_alerts",
    )
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="assigned_monitoring_alerts",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.alert_type}:{self.severity}:{self.status}"


class MerchantWebhookEvent(models.Model):
    credential = models.ForeignKey(
        MerchantApiCredential, on_delete=models.PROTECT, related_name="webhook_events"
    )
    event_type = models.CharField(max_length=64, default="callback")
    nonce = models.CharField(max_length=64, db_index=True)
    payload_hash = models.CharField(max_length=64)
    signature = models.CharField(max_length=128, blank=True, default="")
    signature_valid = models.BooleanField(default=False)
    replay_detected = models.BooleanField(default=False)
    status = models.CharField(max_length=16, default="received")
    response_code = models.PositiveSmallIntegerField(default=200)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")
        unique_together = (("credential", "nonce"),)

    def __str__(self):
        return f"{self.credential.merchant.code}:{self.nonce}:{self.status}"


class AccessReviewRecord(models.Model):
    STATUS_OPEN = "open"
    STATUS_RESOLVED = "resolved"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_RESOLVED, "Resolved"),
    )

    review_no = models.CharField(max_length=40, unique=True)
    user = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="access_review_records"
    )
    issue_type = models.CharField(max_length=64, default="segregation_of_duty")
    details = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    reviewer = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="reviewed_access_records",
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.review_no}:{self.status}"


class OperationCase(models.Model):
    TYPE_COMPLAINT = "complaint"
    TYPE_DISPUTE = "dispute"
    TYPE_REFUND = "refund"
    TYPE_INCIDENT = "incident"
    TYPE_CHOICES = (
        (TYPE_COMPLAINT, "Complaint"),
        (TYPE_DISPUTE, "Dispute"),
        (TYPE_REFUND, "Refund"),
        (TYPE_INCIDENT, "Incident"),
    )

    PRIORITY_LOW = "low"
    PRIORITY_MEDIUM = "medium"
    PRIORITY_HIGH = "high"
    PRIORITY_CRITICAL = "critical"
    PRIORITY_CHOICES = (
        (PRIORITY_LOW, "Low"),
        (PRIORITY_MEDIUM, "Medium"),
        (PRIORITY_HIGH, "High"),
        (PRIORITY_CRITICAL, "Critical"),
    )

    STATUS_OPEN = "open"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_ESCALATED = "escalated"
    STATUS_RESOLVED = "resolved"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_ESCALATED, "Escalated"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_CLOSED, "Closed"),
    )

    case_no = models.CharField(max_length=40, unique=True)
    case_type = models.CharField(max_length=16, choices=TYPE_CHOICES)
    priority = models.CharField(max_length=16, choices=PRIORITY_CHOICES, default=PRIORITY_MEDIUM)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    customer = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="operation_cases",
    )
    merchant = models.ForeignKey(
        Merchant,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="operation_cases",
    )
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="assigned_operation_cases",
    )
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_operation_cases"
    )
    sla_due_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.case_no} ({self.status})"


class OperationCaseNote(models.Model):
    case = models.ForeignKey(
        OperationCase, on_delete=models.CASCADE, related_name="notes"
    )
    note = models.TextField()
    is_internal = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="operation_case_notes"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.case.case_no} note by {self.created_by.username}"


class CustomerCIF(models.Model):
    STATUS_PENDING_KYC = "pending_kyc"
    STATUS_ACTIVE = "active"
    STATUS_BLOCKED = "blocked"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = (
        (STATUS_PENDING_KYC, "Pending KYC"),
        (STATUS_ACTIVE, "Active"),
        (STATUS_BLOCKED, "Blocked"),
        (STATUS_CLOSED, "Closed"),
    )

    cif_no = models.CharField(max_length=40, unique=True)
    user = models.OneToOneField(
        User, on_delete=models.PROTECT, related_name="customer_cif"
    )
    legal_name = models.CharField(max_length=128)
    mobile_no = models.CharField(max_length=40, blank=True, default="")
    email = models.EmailField(blank=True, default="")
    service_class = models.ForeignKey(
        ServiceClassPolicy,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="customer_cifs",
        limit_choices_to={"entity_type": ServiceClassPolicy.ENTITY_CUSTOMER},
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_customer_cifs"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("cif_no",)

    def save(self, *args, **kwargs):
        if self.pk:
            current = CustomerCIF.objects.filter(pk=self.pk).values_list("cif_no", flat=True).first()
            if current and current != self.cif_no:
                raise ValidationError("CIF number is immutable and cannot be changed.")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.cif_no} - {self.legal_name}"


class AnalyticsEvent(models.Model):
    SOURCE_WEB = "web"
    SOURCE_API = "api"
    SOURCE_MOBILE = "mobile"
    SOURCE_CHOICES = (
        (SOURCE_WEB, "Web"),
        (SOURCE_API, "API"),
        (SOURCE_MOBILE, "Mobile"),
    )

    source = models.CharField(max_length=16, choices=SOURCE_CHOICES, default=SOURCE_WEB)
    event_name = models.CharField(max_length=128, db_index=True)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="analytics_events",
    )
    session_id = models.CharField(max_length=64, blank=True, default="")
    external_id = models.CharField(max_length=128, blank=True, default="")
    properties = models.JSONField(default=dict, blank=True)
    sent_to_clevertap = models.BooleanField(default=False)
    clevertap_error = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.source}:{self.event_name}"


class CustomerClassUpgradeRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    )

    cif = models.ForeignKey(
        CustomerCIF,
        on_delete=models.PROTECT,
        related_name="class_upgrade_requests",
    )
    from_service_class = models.ForeignKey(
        ServiceClassPolicy,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="class_upgrade_from_requests",
        limit_choices_to={"entity_type": ServiceClassPolicy.ENTITY_CUSTOMER},
    )
    to_service_class = models.ForeignKey(
        ServiceClassPolicy,
        on_delete=models.PROTECT,
        related_name="class_upgrade_to_requests",
        limit_choices_to={"entity_type": ServiceClassPolicy.ENTITY_CUSTOMER},
    )
    maker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="made_class_upgrade_requests",
    )
    checker = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="checked_class_upgrade_requests",
    )
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
    )
    maker_note = models.TextField(blank=True, default="")
    checker_note = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def clean(self):
        if self.to_service_class.entity_type != ServiceClassPolicy.ENTITY_CUSTOMER:
            raise ValidationError("Target policy must be customer type.")
        if self.from_service_class and self.from_service_class.entity_type != ServiceClassPolicy.ENTITY_CUSTOMER:
            raise ValidationError("Source policy must be customer type.")
        if self.from_service_class_id and self.to_service_class_id and self.from_service_class_id == self.to_service_class_id:
            raise ValidationError("Target policy must be different from current policy.")

    def __str__(self):
        return f"CIF {self.cif.cif_no}: {self.from_service_class_id} -> {self.to_service_class_id} ({self.status})"
