from decimal import Decimal, InvalidOperation

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render

from dj_wallet.models import Transaction, Wallet

from .models import ApprovalRequest, TreasuryAccount, TreasuryTransferRequest, User
from .rbac import (
    BACKOFFICE_ROLES,
    CHECKER_ROLES,
    MAKER_ROLES,
    user_has_any_role,
    user_is_checker,
    user_is_maker,
)


def _parse_amount(raw_value: str) -> Decimal:
    try:
        value = Decimal(raw_value)
    except (InvalidOperation, TypeError):
        raise ValidationError("Invalid amount format.")
    if value <= 0:
        raise ValidationError("Amount must be greater than 0.")
    return value


def _should_use_maker_checker(user) -> bool:
    return user_is_maker(user) and not user_is_checker(user)


def _submit_approval_request(
    *,
    maker: User,
    source_user: User,
    action: str,
    amount: Decimal,
    description: str,
    maker_note: str = "",
    recipient_user: User | None = None,
):
    request_obj = ApprovalRequest.objects.create(
        maker=maker,
        source_user=source_user,
        recipient_user=recipient_user,
        action=action,
        amount=amount,
        description=description,
        maker_note=maker_note,
    )
    return request_obj


@login_required
def dashboard(request):
    wallet = request.user.wallet
    transactions = Transaction.objects.filter(wallet=wallet).order_by("-created_at")[:10]

    return render(
        request,
        "wallets_demo/dashboard.html",
        {
            "transactions": transactions,
        },
    )


@login_required
def backoffice(request):
    if not user_has_any_role(request.user, BACKOFFICE_ROLES):
        raise PermissionDenied("You do not have access to backoffice.")

    recent_transactions = Transaction.objects.select_related("wallet").order_by(
        "-created_at"
    )[:25]
    recent_users = User.objects.order_by("-date_joined")[:10]
    pending_approvals = ApprovalRequest.objects.filter(
        status=ApprovalRequest.STATUS_PENDING
    )[:25]
    my_requests = ApprovalRequest.objects.filter(maker=request.user)[:25]

    context = {
        "recent_transactions": recent_transactions,
        "recent_users": recent_users,
        "pending_approvals": pending_approvals,
        "my_requests": my_requests,
        "total_users": User.objects.count(),
        "total_wallets": Wallet.objects.count(),
        "total_pending_approvals": ApprovalRequest.objects.filter(
            status=ApprovalRequest.STATUS_PENDING
        ).count(),
        "role_names": request.user.role_names,
        "maker_roles": MAKER_ROLES,
        "checker_roles": CHECKER_ROLES,
    }
    return render(request, "wallets_demo/backoffice.html", context)


@login_required
def approval_decision(request, request_id: int):
    if request.method != "POST":
        return redirect("backoffice")
    if not user_has_any_role(request.user, CHECKER_ROLES):
        raise PermissionDenied("You do not have checker role.")

    decision = request.POST.get("decision")
    checker_note = request.POST.get("checker_note", "")
    approval_request = get_object_or_404(ApprovalRequest, id=request_id)

    try:
        if decision == "approve":
            approval_request.approve(request.user, checker_note=checker_note)
            messages.success(request, f"Request #{approval_request.id} approved.")
        elif decision == "reject":
            approval_request.reject(request.user, checker_note=checker_note)
            messages.success(request, f"Request #{approval_request.id} rejected.")
        else:
            messages.error(request, "Invalid decision action.")
    except Exception as exc:
        messages.error(request, f"Decision failed: {exc}")
    return redirect("backoffice")


@login_required
def treasury_dashboard(request):
    if not user_has_any_role(request.user, BACKOFFICE_ROLES):
        raise PermissionDenied("You do not have access to treasury.")

    if request.method == "POST":
        if not user_has_any_role(request.user, MAKER_ROLES):
            raise PermissionDenied("You do not have maker role for treasury requests.")
        try:
            from_account = TreasuryAccount.objects.get(id=request.POST.get("from_account"))
            to_account = TreasuryAccount.objects.get(id=request.POST.get("to_account"))
            amount = _parse_amount(request.POST.get("amount"))
            reason = request.POST.get("reason", "")
            maker_note = request.POST.get("maker_note", "")
            req = TreasuryTransferRequest.objects.create(
                maker=request.user,
                from_account=from_account,
                to_account=to_account,
                amount=amount,
                reason=reason,
                maker_note=maker_note,
            )
            messages.success(
                request, f"Treasury transfer request #{req.id} submitted for approval."
            )
            return redirect("treasury_dashboard")
        except Exception as exc:
            messages.error(request, f"Treasury request failed: {exc}")

    accounts = TreasuryAccount.objects.filter(is_active=True).order_by("name")
    pending_requests = TreasuryTransferRequest.objects.filter(
        status=TreasuryTransferRequest.STATUS_PENDING
    )[:25]
    my_requests = TreasuryTransferRequest.objects.filter(maker=request.user)[:25]
    return render(
        request,
        "wallets_demo/treasury.html",
        {
            "accounts": accounts,
            "pending_requests": pending_requests,
            "my_requests": my_requests,
            "can_make_treasury_request": user_has_any_role(request.user, MAKER_ROLES),
            "can_check_treasury_request": user_has_any_role(request.user, CHECKER_ROLES),
        },
    )


@login_required
def treasury_decision(request, request_id: int):
    if request.method != "POST":
        return redirect("treasury_dashboard")
    if not user_has_any_role(request.user, CHECKER_ROLES):
        raise PermissionDenied("You do not have checker role.")

    req = get_object_or_404(TreasuryTransferRequest, id=request_id)
    decision = request.POST.get("decision")
    checker_note = request.POST.get("checker_note", "")
    try:
        if decision == "approve":
            req.approve(request.user, checker_note=checker_note)
            messages.success(request, f"Treasury request #{req.id} approved.")
        elif decision == "reject":
            req.reject(request.user, checker_note=checker_note)
            messages.success(request, f"Treasury request #{req.id} rejected.")
        else:
            messages.error(request, "Invalid decision.")
    except Exception as exc:
        messages.error(request, f"Treasury decision failed: {exc}")
    return redirect("treasury_dashboard")


@login_required
def deposit(request):
    if request.method == "POST":
        description = request.POST.get("description", "Manual Deposit")
        maker_note = request.POST.get("maker_note", "")

        try:
            amount = _parse_amount(request.POST.get("amount"))
            if _should_use_maker_checker(request.user):
                approval_request = _submit_approval_request(
                    maker=request.user,
                    source_user=request.user,
                    action=ApprovalRequest.ACTION_DEPOSIT,
                    amount=amount,
                    description=description,
                    maker_note=maker_note,
                )
                messages.success(
                    request,
                    f"Deposit request #{approval_request.id} submitted for checker approval.",
                )
                return redirect("dashboard")

            with transaction.atomic():
                request.user.deposit(amount, meta={"description": description})
            messages.success(request, f"Successfully deposited ${amount}.")
            return redirect("dashboard")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Error during deposit: {exc}")

    return render(request, "wallets_demo/deposit.html")


@login_required
def withdraw(request):
    if request.method == "POST":
        description = request.POST.get("description", "Manual Withdrawal")
        maker_note = request.POST.get("maker_note", "")

        try:
            amount = _parse_amount(request.POST.get("amount"))
            if request.user.balance < amount:
                messages.error(request, "Insufficient funds.")
                return render(request, "wallets_demo/withdraw.html")

            if _should_use_maker_checker(request.user):
                approval_request = _submit_approval_request(
                    maker=request.user,
                    source_user=request.user,
                    action=ApprovalRequest.ACTION_WITHDRAW,
                    amount=amount,
                    description=description,
                    maker_note=maker_note,
                )
                messages.success(
                    request,
                    f"Withdrawal request #{approval_request.id} submitted for checker approval.",
                )
                return redirect("dashboard")

            with transaction.atomic():
                request.user.withdraw(amount, meta={"description": description})
            messages.success(request, f"Successfully withdrew ${amount}.")
            return redirect("dashboard")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Error during withdrawal: {exc}")

    return render(request, "wallets_demo/withdraw.html")


@login_required
def transfer(request):
    users = User.objects.exclude(id=request.user.id)

    if request.method == "POST":
        recipient_id = request.POST.get("recipient")
        description = request.POST.get("description", "Wallet Transfer")
        maker_note = request.POST.get("maker_note", "")

        try:
            amount = _parse_amount(request.POST.get("amount"))
            recipient = User.objects.get(id=recipient_id)

            if request.user.balance < amount:
                messages.error(request, "Insufficient funds.")
                return render(request, "wallets_demo/transfer.html", {"users": users})

            if _should_use_maker_checker(request.user):
                approval_request = _submit_approval_request(
                    maker=request.user,
                    source_user=request.user,
                    recipient_user=recipient,
                    action=ApprovalRequest.ACTION_TRANSFER,
                    amount=amount,
                    description=description,
                    maker_note=maker_note,
                )
                messages.success(
                    request,
                    f"Transfer request #{approval_request.id} submitted for checker approval.",
                )
                return redirect("dashboard")

            with transaction.atomic():
                request.user.transfer(
                    recipient,
                    amount,
                    meta={"description": description},
                )
            messages.success(
                request,
                f"Successfully transferred ${amount} to {recipient.username}.",
            )
            return redirect("dashboard")
        except User.DoesNotExist:
            messages.error(request, "Recipient not found.")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Error during transfer: {exc}")

    return render(request, "wallets_demo/transfer.html", {"users": users})


def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists.")
            else:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                )
                login(request, user)
                user.deposit(100, meta={"description": "Welcome Bonus"})
                messages.success(
                    request,
                    "Account created! You received a $100 welcome bonus.",
                )
                return redirect("dashboard")
        except Exception as exc:
            messages.error(request, f"Error creating account: {exc}")

    return render(request, "wallets_demo/register.html")
