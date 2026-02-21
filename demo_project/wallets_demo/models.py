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

class User(WalletMixin, AbstractUser):
    @property
    def role_names(self) -> list[str]:
        return list(self.groups.values_list("name", flat=True))

    def has_role(self, role_name: str) -> bool:
        return user_has_any_role(self, [role_name])

    def has_any_role(self, role_names: list[str] | tuple[str, ...]) -> bool:
        return user_has_any_role(self, role_names)


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
    contact_email = models.EmailField(blank=True, default="")
    contact_phone = models.CharField(max_length=40, blank=True, default="")
    owner = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="managed_merchants",
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
