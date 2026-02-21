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
