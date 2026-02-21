from decimal import Decimal
from unittest.mock import patch

from django.test import Client, TestCase
from django.urls import reverse
from dj_wallet.models import Wallet

from .models import (
    ApprovalRequest,
    BackofficeAuditLog,
    ChartOfAccount,
    FxRate,
    JournalEntry,
    JournalLine,
    TreasuryAccount,
    TreasuryTransferRequest,
    User,
)
from .rbac import assign_roles, seed_role_groups


class RBACMakerCheckerTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.maker = User.objects.create_user(username="maker", password="pass12345")
        self.checker = User.objects.create_user(username="checker", password="pass12345")
        assign_roles(self.maker, ["finance"])
        assign_roles(self.checker, ["admin"])
        self.maker.deposit(100)

    def test_maker_deposit_creates_pending_request(self):
        self.client.login(username="maker", password="pass12345")
        response = self.client.post(
            reverse("deposit"),
            {"amount": "10.00", "description": "topup", "maker_note": "needs approval"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ApprovalRequest.objects.count(), 1)
        req = ApprovalRequest.objects.get()
        self.assertEqual(req.status, ApprovalRequest.STATUS_PENDING)
        self.assertEqual(float(self.maker.balance), 100.0)

    def test_checker_can_approve_request(self):
        req = ApprovalRequest.objects.create(
            maker=self.maker,
            source_user=self.maker,
            action=ApprovalRequest.ACTION_DEPOSIT,
            amount="25.00",
            description="manual",
            maker_note="approve this",
        )

        self.client.login(username="checker", password="pass12345")
        response = self.client.post(
            reverse("approval_decision", kwargs={"request_id": req.id}),
            {"decision": "approve", "checker_note": "ok"},
        )
        self.assertEqual(response.status_code, 302)
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalRequest.STATUS_APPROVED)
        self.maker.refresh_from_db()
        self.assertEqual(float(self.maker.balance), 125.0)


class TreasuryWorkflowTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.maker = User.objects.create_user(username="treasury_maker", password="pass12345")
        self.checker = User.objects.create_user(
            username="treasury_checker", password="pass12345"
        )
        assign_roles(self.maker, ["finance"])
        assign_roles(self.checker, ["admin"])
        self.from_account = TreasuryAccount.objects.create(
            name="operating-usd",
            currency="USD",
            balance="1000.00",
        )
        self.to_account = TreasuryAccount.objects.create(
            name="settlement-usd",
            currency="USD",
            balance="100.00",
        )

    def test_submit_treasury_request(self):
        self.client.login(username="treasury_maker", password="pass12345")
        response = self.client.post(
            reverse("treasury_dashboard"),
            {
                "from_account": self.from_account.id,
                "to_account": self.to_account.id,
                "amount": "200.00",
                "reason": "liquidity move",
            },
        )
        self.assertEqual(response.status_code, 302)
        req = TreasuryTransferRequest.objects.get()
        self.assertEqual(req.status, TreasuryTransferRequest.STATUS_PENDING)

    def test_checker_approves_treasury_request(self):
        req = TreasuryTransferRequest.objects.create(
            maker=self.maker,
            from_account=self.from_account,
            to_account=self.to_account,
            amount="250.00",
            reason="top up",
        )
        self.client.login(username="treasury_checker", password="pass12345")
        response = self.client.post(
            reverse("treasury_decision", kwargs={"request_id": req.id}),
            {"decision": "approve", "checker_note": "approved"},
        )
        self.assertEqual(response.status_code, 302)
        req.refresh_from_db()
        self.from_account.refresh_from_db()
        self.to_account.refresh_from_db()
        self.assertEqual(req.status, TreasuryTransferRequest.STATUS_APPROVED)
        self.assertEqual(str(self.from_account.balance), "750.00")
        self.assertEqual(str(self.to_account.balance), "350.00")


class RBACManagementViewTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.admin = User.objects.create_user(username="rbac_admin", password="pass12345")
        self.staff = User.objects.create_user(username="staff_user", password="pass12345")
        assign_roles(self.admin, ["admin"])

    def test_admin_can_assign_roles_from_rbac_view(self):
        self.client.login(username="rbac_admin", password="pass12345")
        response = self.client.post(
            reverse("rbac_management"),
            {
                "user_id": self.staff.id,
                "role_finance": "on",
                "role_operation": "on",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.staff.refresh_from_db()
        self.assertCountEqual(self.staff.role_names, ["finance", "operation"])


class AccountingWorkflowTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.finance = User.objects.create_user(username="finance_user", password="pass12345")
        self.checker = User.objects.create_user(username="checker_user", password="pass12345")
        assign_roles(self.finance, ["finance"])
        assign_roles(self.checker, ["admin"])
        self.cash = ChartOfAccount.objects.create(
            code="1010",
            name="Cash and Bank",
            account_type=ChartOfAccount.TYPE_ASSET,
            currency="USD",
        )
        self.liability = ChartOfAccount.objects.create(
            code="2010",
            name="Customer Wallet Liability",
            account_type=ChartOfAccount.TYPE_LIABILITY,
            currency="USD",
        )

    def test_balanced_entry_can_be_posted(self):
        entry = JournalEntry.objects.create(
            entry_no="JE-TEST-1",
            created_by=self.finance,
            description="Initial load",
        )
        JournalLine.objects.create(entry=entry, account=self.cash, debit="100.00", credit="0")
        JournalLine.objects.create(entry=entry, account=self.liability, debit="0", credit="100.00")

        entry.post(self.checker)
        entry.refresh_from_db()
        self.assertEqual(entry.status, JournalEntry.STATUS_POSTED)

    def test_unbalanced_entry_cannot_be_posted(self):
        entry = JournalEntry.objects.create(
            entry_no="JE-TEST-2",
            created_by=self.finance,
            description="Bad entry",
        )
        JournalLine.objects.create(entry=entry, account=self.cash, debit="120.00", credit="0")
        JournalLine.objects.create(entry=entry, account=self.liability, debit="0", credit="100.00")

        with self.assertRaises(Exception):
            entry.post(self.checker)


class FxWorkflowTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.user = User.objects.create_user(username="fx_user", password="pass12345")
        self.user.deposit(200)
        FxRate.objects.create(base_currency="USD", quote_currency="EUR", rate="0.90000000")

    def test_wallet_fx_exchange(self):
        self.client.login(username="fx_user", password="pass12345")
        response = self.client.post(
            reverse("wallet_fx_exchange"),
            {"from_currency": "USD", "to_currency": "EUR", "amount": "100.00"},
        )
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        usd_wallet = self.user.get_wallet("default")
        eur_wallet = self.user.get_wallet("eur")
        self.assertEqual(usd_wallet.balance, Decimal("100.00000000"))
        self.assertEqual(eur_wallet.balance, Decimal("90.00000000"))


class DashboardMetaCompatibilityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="meta_user", password="pass12345")
        wallet = self.user.get_wallet("default")
        Wallet.objects.filter(id=wallet.id).update(meta=None)

    def test_dashboard_handles_null_wallet_meta(self):
        self.client.login(username="meta_user", password="pass12345")
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)


class FxProviderSyncTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.user = User.objects.create_user(username="fx_admin", password="pass12345")
        assign_roles(self.user, ["finance"])

    def test_fx_management_can_sync_external_rates(self):
        payload = b'{"amount":1.0,"base":"USD","date":"2026-02-21","rates":{"EUR":0.93,"SGD":1.34}}'

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return payload

        self.client.login(username="fx_admin", password="pass12345")
        with patch("wallets_demo.fx_provider.urlopen", return_value=_Resp()):
            response = self.client.post(
                reverse("fx_management"),
                {"action": "sync_external", "sync_base_currency": "USD"},
            )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(FxRate.objects.filter(base_currency="USD", quote_currency="EUR").exists())
        self.assertTrue(FxRate.objects.filter(base_currency="USD", quote_currency="SGD").exists())


class BackofficeAuditExportTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.super_admin = User.objects.create_user(
            username="super_export",
            email="super_export@example.com",
            password="pass12345",
        )
        assign_roles(self.super_admin, ["super_admin"])
        BackofficeAuditLog.objects.create(
            actor=self.super_admin,
            action="test.action",
            target_type="Test",
            target_id="1",
            metadata_json={"check": "ok"},
        )

    def test_super_admin_can_export_audit_jsonl(self):
        self.client.login(username="super_export", password="pass12345")
        response = self.client.get(reverse("backoffice_audit_export"), {"format": "jsonl", "days": 7})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-Audit-Export-Signature-Alg"], "HMAC-SHA256")
        self.assertIn("X-Audit-Export-Signature", response)
        self.assertIn("X-Audit-Export-SHA256", response)
        self.assertIn("test.action", response.content.decode("utf-8"))
