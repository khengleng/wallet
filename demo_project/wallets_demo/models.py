from decimal import Decimal

from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone
from dj_wallet.mixins import WalletMixin
from .rbac import user_has_any_role, user_is_checker

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
        }
        try:
            with transaction.atomic():
                if self.action == self.ACTION_DEPOSIT:
                    self.source_user.deposit(self.amount, meta=meta)
                elif self.action == self.ACTION_WITHDRAW:
                    self.source_user.withdraw(self.amount, meta=meta)
                elif self.action == self.ACTION_TRANSFER:
                    if self.recipient_user is None:
                        raise ValidationError("Recipient is required for transfer.")
                    self.source_user.transfer(self.recipient_user, self.amount, meta=meta)
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
