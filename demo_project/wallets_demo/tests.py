from decimal import Decimal
import io
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from dj_wallet.models import Wallet

from .models import (
    AccessReviewRecord,
    AccountingPeriodClose,
    ApprovalRequest,
    BackofficeAuditLog,
    ChartOfAccount,
    ChargebackCase,
    ChargebackEvidence,
    CustomerCIF,
    DisputeRefundRequest,
    FxRate,
    JournalEntry,
    JournalEntryApproval,
    JournalBackdateApproval,
    JournalLine,
    Merchant,
    MerchantApiCredential,
    MerchantCashflowEvent,
    MerchantFeeRule,
    MerchantKYBRequest,
    MerchantLoyaltyProgram,
    MerchantRiskProfile,
    MerchantSettlementRecord,
    MerchantWebhookEvent,
    MerchantWalletCapability,
    OperationCase,
    ReconciliationBreak,
    ReconciliationRun,
    SettlementException,
    SettlementPayout,
    TransactionMonitoringAlert,
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


class AccountingOpsWorkbenchTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.finance = User.objects.create_user(username="finance_ops", password="pass12345")
        self.checker = User.objects.create_user(username="checker_ops", password="pass12345")
        assign_roles(self.finance, ["finance"])
        assign_roles(self.checker, ["admin"])
        self.cash = ChartOfAccount.objects.create(
            code="1011",
            name="Cash Ops",
            account_type=ChartOfAccount.TYPE_ASSET,
            currency="USD",
        )
        self.liability = ChartOfAccount.objects.create(
            code="2011",
            name="Liability Ops",
            account_type=ChartOfAccount.TYPE_LIABILITY,
            currency="USD",
        )

    def _create_draft_entry(self) -> JournalEntry:
        entry = JournalEntry.objects.create(
            entry_no="JE-OPS-1",
            created_by=self.finance,
            description="Ops draft",
            currency="USD",
        )
        JournalLine.objects.create(entry=entry, account=self.cash, debit="50.00", credit="0")
        JournalLine.objects.create(entry=entry, account=self.liability, debit="0", credit="50.00")
        return entry

    def test_submit_and_approve_journal_posting_queue(self):
        entry = self._create_draft_entry()
        self.client.login(username="finance_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_submit_for_checker",
                "entry_id": entry.id,
                "reason": "ready for posting",
            },
        )
        self.assertEqual(response.status_code, 302)
        approval = JournalEntryApproval.objects.get(entry=entry)
        self.assertEqual(approval.status, JournalEntryApproval.STATUS_PENDING)

        self.client.logout()
        self.client.login(username="checker_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_approval_decision",
                "approval_id": approval.id,
                "decision": "approve",
                "checker_note": "approved",
            },
        )
        self.assertEqual(response.status_code, 302)
        approval.refresh_from_db()
        entry.refresh_from_db()
        self.assertEqual(approval.status, JournalEntryApproval.STATUS_APPROVED)
        self.assertEqual(entry.status, JournalEntry.STATUS_POSTED)

    def test_reversal_request_creates_pending_approval(self):
        posted = self._create_draft_entry()
        posted.post(self.checker)
        self.client.login(username="finance_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_reversal_request",
                "source_entry_id": posted.id,
                "reason": "duplicate posting",
            },
        )
        self.assertEqual(response.status_code, 302)
        approval = JournalEntryApproval.objects.filter(
            source_entry=posted,
            request_type=JournalEntryApproval.TYPE_REVERSAL,
        ).first()
        self.assertIsNotNone(approval)
        self.assertEqual(approval.status, JournalEntryApproval.STATUS_PENDING)

    def test_checker_reject_requires_note(self):
        entry = self._create_draft_entry()
        approval = JournalEntryApproval.objects.create(
            entry=entry,
            request_type=JournalEntryApproval.TYPE_POST,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="review",
        )
        self.client.login(username="checker_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_approval_decision",
                "approval_id": approval.id,
                "decision": "reject",
                "checker_note": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        approval.refresh_from_db()
        self.assertEqual(approval.status, JournalEntryApproval.STATUS_PENDING)

    def test_maker_cannot_decide_own_request(self):
        entry = self._create_draft_entry()
        approval = JournalEntryApproval.objects.create(
            entry=entry,
            request_type=JournalEntryApproval.TYPE_POST,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="maker cannot self approve",
        )
        self.client.login(username="finance_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_approval_decision",
                "approval_id": approval.id,
                "decision": "approve",
                "checker_note": "self",
            },
        )
        self.assertEqual(response.status_code, 200)
        approval.refresh_from_db()
        self.assertEqual(approval.status, JournalEntryApproval.STATUS_PENDING)

    def test_reclass_amount_cannot_exceed_source_exposure(self):
        posted = self._create_draft_entry()
        posted.post(self.checker)
        self.client.login(username="finance_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_reclass_request",
                "source_entry_id": posted.id,
                "from_account_id": self.cash.id,
                "to_account_id": self.liability.id,
                "amount": "999.00",
                "reason": "invalid large amount",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            JournalEntryApproval.objects.filter(
                source_entry=posted, request_type=JournalEntryApproval.TYPE_RECLASS
            ).exists()
        )

    def test_export_approval_queue_csv(self):
        entry = self._create_draft_entry()
        JournalEntryApproval.objects.create(
            entry=entry,
            request_type=JournalEntryApproval.TYPE_POST,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="export me",
        )
        self.client.login(username="finance_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_export",
                "export_type": "approval_queue",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Type"].startswith("text/csv"))
        body = response.content.decode("utf-8")
        self.assertIn("entry_no,request_type,status", body)
        self.assertIn("JE-OPS-1", body)

    def test_non_accounting_user_forbidden(self):
        outsider = User.objects.create_user(username="outsider_acc", password="pass12345")
        self.client.login(username="outsider_acc", password="pass12345")
        response = self.client.get(reverse("accounting_dashboard"))
        self.assertEqual(response.status_code, 403)

    def test_queue_filter_by_type(self):
        post_entry = self._create_draft_entry()
        JournalEntryApproval.objects.create(
            entry=post_entry,
            request_type=JournalEntryApproval.TYPE_POST,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="post",
        )
        source_posted = JournalEntry.objects.create(
            entry_no="JE-OPS-2",
            created_by=self.finance,
            description="Posted source",
            currency="USD",
        )
        JournalLine.objects.create(entry=source_posted, account=self.cash, debit="30.00", credit="0")
        JournalLine.objects.create(entry=source_posted, account=self.liability, debit="0", credit="30.00")
        source_posted.post(self.checker)
        reversal_entry = JournalEntry.objects.create(
            entry_no="JE-OPS-3",
            created_by=self.finance,
            description="Reversal draft",
            currency="USD",
        )
        JournalLine.objects.create(entry=reversal_entry, account=self.cash, debit="0", credit="30.00")
        JournalLine.objects.create(entry=reversal_entry, account=self.liability, debit="30.00", credit="0")
        JournalEntryApproval.objects.create(
            entry=reversal_entry,
            source_entry=source_posted,
            request_type=JournalEntryApproval.TYPE_REVERSAL,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="reversal",
        )

        self.client.login(username="checker_ops", password="pass12345")
        response = self.client.get(
            reverse("accounting_dashboard"),
            {"queue_type": "reversal", "queue_status": "pending"},
        )
        self.assertEqual(response.status_code, 200)
        queue_page = response.context["approval_queue"]
        self.assertGreaterEqual(len(queue_page.object_list), 1)
        self.assertTrue(
            all(req.request_type == JournalEntryApproval.TYPE_REVERSAL for req in queue_page.object_list)
        )

    @override_settings(
        ACCOUNTING_PRIV_ACTION_DAILY_THRESHOLD=1,
        ACCOUNTING_BUSINESS_HOUR_START=0,
        ACCOUNTING_BUSINESS_HOUR_END=24,
    )
    def test_privileged_action_burst_creates_monitoring_alert(self):
        posted = self._create_draft_entry()
        posted.post(self.checker)
        prior_entry = JournalEntry.objects.create(
            entry_no="JE-OPS-4",
            created_by=self.finance,
            description="Prior privileged",
            currency="USD",
        )
        JournalLine.objects.create(entry=prior_entry, account=self.cash, debit="10.00", credit="0")
        JournalLine.objects.create(entry=prior_entry, account=self.liability, debit="0", credit="10.00")
        JournalEntryApproval.objects.create(
            entry=prior_entry,
            source_entry=posted,
            request_type=JournalEntryApproval.TYPE_REVERSAL,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="seed prior privileged request",
        )
        self.client.login(username="finance_ops", password="pass12345")
        response = self.client.post(
            reverse("accounting_dashboard"),
            {
                "form_type": "journal_reversal_request",
                "source_entry_id": posted.id,
                "reason": "new privileged action",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            TransactionMonitoringAlert.objects.filter(
                alert_type="accounting_privileged_action_burst",
                user=self.finance,
            ).exists()
        )


class OpsWorkQueueAccountingTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.finance = User.objects.create_user(username="queue_finance", password="pass12345")
        self.admin = User.objects.create_user(username="queue_admin", password="pass12345")
        assign_roles(self.finance, ["finance"])
        assign_roles(self.admin, ["admin"])
        self.asset = ChartOfAccount.objects.create(
            code="1012",
            name="Queue Asset",
            account_type=ChartOfAccount.TYPE_ASSET,
            currency="USD",
        )
        self.liability = ChartOfAccount.objects.create(
            code="2012",
            name="Queue Liability",
            account_type=ChartOfAccount.TYPE_LIABILITY,
            currency="USD",
        )

    def test_ops_queue_includes_journal_posting_items(self):
        entry = JournalEntry.objects.create(
            entry_no="JE-QUEUE-1",
            created_by=self.finance,
            description="Queue test",
            currency="USD",
        )
        JournalLine.objects.create(entry=entry, account=self.asset, debit="77.00", credit="0")
        JournalLine.objects.create(entry=entry, account=self.liability, debit="0", credit="77.00")
        JournalEntryApproval.objects.create(
            entry=entry,
            request_type=JournalEntryApproval.TYPE_POST,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="awaiting checker",
        )

        self.client.login(username="queue_admin", password="pass12345")
        response = self.client.get(reverse("ops_work_queue"), {"type": "journal_posting"})
        self.assertEqual(response.status_code, 200)
        queue_items = response.context["queue_items"]
        self.assertTrue(any(item["queue_type"] == "journal_posting" for item in queue_items))
        self.assertContains(response, "JE-QUEUE-1")


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


class CustomerCIFWalletManagementTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.admin = User.objects.create_user(
            username="wallet_admin",
            email="wallet_admin@example.com",
            password="pass12345",
        )
        assign_roles(self.admin, ["admin"])
        self.user = User.objects.create_user(
            username="wallet_customer",
            email="wallet_customer@example.com",
            password="pass12345",
        )
        self.cif = CustomerCIF.objects.create(
            cif_no="CIF-0001",
            user=self.user,
            legal_name="Wallet Customer",
            mobile_no="+12025550100",
            email=self.user.email,
            status=CustomerCIF.STATUS_ACTIVE,
            created_by=self.admin,
        )
        self.client.login(username="wallet_admin", password="pass12345")

    def test_cif_number_is_immutable(self):
        self.cif.cif_no = "CIF-NEW-0001"
        with self.assertRaises(ValidationError):
            self.cif.save()

    def test_wallet_management_rejects_cif_number_change(self):
        response = self.client.post(
            reverse("wallet_management"),
            {
                "form_type": "cif_onboard",
                "user_id": self.user.id,
                "cif_no": "CIF-OTHER-999",
                "legal_name": "Wallet Customer Updated",
                "mobile_no": "+12025550199",
                "email": "wallet_customer_updated@example.com",
                "status": CustomerCIF.STATUS_ACTIVE,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.cif.refresh_from_db()
        self.assertEqual(self.cif.cif_no, "CIF-0001")

    def test_wallet_management_freeze_unfreeze_with_cif_selector(self):
        wallet = self.user.get_wallet("default")
        self.assertFalse(wallet.is_frozen)

        response = self.client.post(
            reverse("wallet_management"),
            {
                "form_type": "wallet_toggle_freeze",
                "holder_scope": "user",
                "cif_id": self.cif.id,
                "wallet_slug": "default",
                "action": "freeze",
            },
        )
        self.assertEqual(response.status_code, 302)
        wallet.refresh_from_db()
        self.assertTrue(wallet.is_frozen)

        response = self.client.post(
            reverse("wallet_management"),
            {
                "form_type": "wallet_toggle_freeze",
                "holder_scope": "user",
                "cif_id": self.cif.id,
                "wallet_slug": "default",
                "action": "unfreeze",
            },
        )
        self.assertEqual(response.status_code, 302)
        wallet.refresh_from_db()
        self.assertFalse(wallet.is_frozen)

    def test_wallet_management_freeze_with_merchant_selector(self):
        merchant = Merchant.objects.create(
            code="MRC-1001",
            name="Merchant 1001",
            created_by=self.admin,
            updated_by=self.admin,
            owner=self.admin,
        )
        merchant_wallet = merchant.get_wallet("default")
        self.assertFalse(merchant_wallet.is_frozen)

        response = self.client.post(
            reverse("wallet_management"),
            {
                "form_type": "wallet_toggle_freeze",
                "holder_scope": "merchant",
                "merchant_id": merchant.id,
                "wallet_slug": "default",
                "action": "freeze",
            },
        )
        self.assertEqual(response.status_code, 302)
        merchant_wallet.refresh_from_db()
        self.assertTrue(merchant_wallet.is_frozen)

    def test_wallet_management_cif_search_and_pagination(self):
        for index in range(2, 31):
            user = User.objects.create_user(
                username=f"wallet_customer_{index:02d}",
                email=f"wallet_customer_{index:02d}@example.com",
                password="pass12345",
            )
            CustomerCIF.objects.create(
                cif_no=f"CIF-{index:04d}",
                user=user,
                legal_name=f"Wallet Customer {index:02d}",
                email=user.email,
                status=CustomerCIF.STATUS_ACTIVE,
                created_by=self.admin,
            )

        response = self.client.get(reverse("wallet_management"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["customer_cifs"].paginator.num_pages, 2)

        response = self.client.get(reverse("wallet_management"), {"q": "CIF-0030"})
        self.assertEqual(response.status_code, 200)
        filtered = list(response.context["customer_cifs"].object_list)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].cif_no, "CIF-0030")


class MerchantEnterpriseOperationsTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.admin = User.objects.create_user(
            username="merchant_admin",
            email="merchant_admin@example.com",
            password="pass12345",
        )
        self.maker = User.objects.create_user(username="merchant_maker", password="pass12345")
        self.checker = User.objects.create_user(username="merchant_checker", password="pass12345")
        self.customer = User.objects.create_user(username="merchant_customer", password="pass12345")
        assign_roles(self.admin, ["admin"])
        assign_roles(self.maker, ["operation"])
        assign_roles(self.checker, ["risk"])
        self.customer.deposit(200)
        self.merchant = Merchant.objects.create(
            code="MOPS001",
            name="Merchant Ops",
            settlement_currency="USD",
            created_by=self.admin,
            updated_by=self.admin,
            owner=self.admin,
        )
        MerchantWalletCapability.objects.create(
            merchant=self.merchant,
            supports_b2b=True,
            supports_b2c=True,
            supports_c2b=True,
            supports_p2g=False,
            supports_g2p=False,
        )
        MerchantLoyaltyProgram.objects.create(merchant=self.merchant)
        MerchantRiskProfile.objects.create(
            merchant=self.merchant,
            daily_txn_limit=100,
            daily_amount_limit=Decimal("1000000"),
            single_txn_limit=Decimal("100000"),
            reserve_ratio_bps=0,
            require_manual_review_above=Decimal("0"),
            is_high_risk=False,
            updated_by=self.admin,
        )

    def test_cashflow_applies_fee_rule(self):
        MerchantFeeRule.objects.create(
            merchant=self.merchant,
            flow_type="c2b",
            percent_bps=100,
            fixed_fee=Decimal("1.00"),
            minimum_fee=Decimal("0"),
            maximum_fee=Decimal("0"),
            is_active=True,
            created_by=self.admin,
            updated_by=self.admin,
        )
        self.client.login(username="merchant_admin", password="pass12345")
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "cashflow_event_create",
                "merchant_id": self.merchant.id,
                "flow_type": "c2b",
                "user_id": self.customer.id,
                "currency": "USD",
                "amount": "100.00",
                "reference": "FEE-APPLY",
                "note": "fee test",
            },
        )
        self.assertIn(response.status_code, (200, 302))
        messages_text = []
        if getattr(response, "context", None) is not None and "messages" in response.context:
            messages_text = [str(m) for m in response.context["messages"]]
        self.assertTrue(
            MerchantCashflowEvent.objects.filter(reference="FEE-APPLY").exists(),
            f"cashflow not created; messages={messages_text}",
        )
        event = MerchantCashflowEvent.objects.get(reference="FEE-APPLY")
        self.assertEqual(event.fee_amount, Decimal("2.00"))
        self.assertEqual(event.net_amount, Decimal("98.00"))

    def test_cashflow_blocked_by_risk_single_txn_limit(self):
        risk = self.merchant.risk_profile
        risk.single_txn_limit = Decimal("25.00")
        risk.save(update_fields=["single_txn_limit", "updated_at"])

        self.client.login(username="merchant_admin", password="pass12345")
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "cashflow_event_create",
                "merchant_id": self.merchant.id,
                "flow_type": "c2b",
                "user_id": self.customer.id,
                "currency": "USD",
                "amount": "30.00",
                "reference": "RISK-BLOCK",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            MerchantCashflowEvent.objects.filter(reference="RISK-BLOCK").exists()
        )

    def test_settlement_generation_marks_events(self):
        MerchantCashflowEvent.objects.create(
            merchant=self.merchant,
            flow_type="c2b",
            amount=Decimal("100.00"),
            fee_amount=Decimal("2.00"),
            net_amount=Decimal("98.00"),
            currency="USD",
            from_user=self.customer,
            created_by=self.admin,
            reference="STL-1",
        )
        MerchantCashflowEvent.objects.create(
            merchant=self.merchant,
            flow_type="c2b",
            amount=Decimal("40.00"),
            fee_amount=Decimal("1.00"),
            net_amount=Decimal("39.00"),
            currency="USD",
            from_user=self.customer,
            created_by=self.admin,
            reference="STL-2",
        )
        self.client.login(username="merchant_admin", password="pass12345")
        today = str(self.merchant.created_at.date())
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "merchant_settlement_create",
                "merchant_id": self.merchant.id,
                "currency": "USD",
                "period_start": today,
                "period_end": today,
            },
        )
        self.assertEqual(response.status_code, 302)
        settlement = MerchantSettlementRecord.objects.get(merchant=self.merchant)
        self.assertEqual(settlement.event_count, 2)
        self.assertEqual(settlement.gross_amount, Decimal("140.00"))
        self.assertEqual(settlement.fee_amount, Decimal("3.00"))
        self.assertEqual(settlement.net_amount, Decimal("137.00"))
        self.assertEqual(
            MerchantCashflowEvent.objects.filter(settlement_reference=settlement.settlement_no).count(),
            2,
        )

    def test_kyb_maker_checker_approval(self):
        self.client.login(username="merchant_maker", password="pass12345")
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "merchant_kyb_submit",
                "merchant_id": self.merchant.id,
                "legal_name": "Merchant Ops Legal",
                "registration_number": "REG-7788",
                "tax_id": "TAX-7788",
                "country_code": "SG",
                "risk_note": "reviewed",
            },
        )
        self.assertEqual(response.status_code, 302)
        kyb = MerchantKYBRequest.objects.get(merchant=self.merchant)
        self.assertEqual(kyb.status, MerchantKYBRequest.STATUS_PENDING)

        self.client.logout()
        self.client.login(username="merchant_checker", password="pass12345")
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "merchant_kyb_decision",
                "kyb_request_id": kyb.id,
                "decision": "approved",
                "checker_note": "ok",
            },
        )
        self.assertEqual(response.status_code, 302)
        kyb.refresh_from_db()
        self.merchant.refresh_from_db()
        self.assertEqual(kyb.status, MerchantKYBRequest.STATUS_APPROVED)
        self.assertEqual(self.merchant.name, "Merchant Ops Legal")


class MerchantOpsWorkflowTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.admin = User.objects.create_user(username="ops_admin", password="pass12345")
        self.ops = User.objects.create_user(username="ops_user", password="pass12345")
        self.risk = User.objects.create_user(username="risk_user", password="pass12345")
        self.customer = User.objects.create_user(username="ops_customer", password="pass12345")
        assign_roles(self.admin, ["admin"])
        assign_roles(self.ops, ["operation"])
        assign_roles(self.risk, ["risk"])
        self.customer.deposit(300)
        self.merchant = Merchant.objects.create(
            code="MOPS200",
            name="Merchant 200",
            created_by=self.admin,
            updated_by=self.admin,
            owner=self.admin,
        )
        MerchantWalletCapability.objects.create(merchant=self.merchant)
        MerchantLoyaltyProgram.objects.create(merchant=self.merchant)
        MerchantRiskProfile.objects.create(
            merchant=self.merchant,
            daily_txn_limit=1000,
            daily_amount_limit=Decimal("9999999"),
            single_txn_limit=Decimal("999999"),
            reserve_ratio_bps=0,
            require_manual_review_above=Decimal("0"),
            updated_by=self.admin,
        )
        self.merchant.deposit(100)
        self.case = OperationCase.objects.create(
            case_no="CASE-TEST-OPS-1",
            case_type=OperationCase.TYPE_DISPUTE,
            priority=OperationCase.PRIORITY_MEDIUM,
            title="Dispute case",
            customer=self.customer,
            merchant=self.merchant,
            assigned_to=self.ops,
            created_by=self.ops,
        )

    def test_dispute_refund_maker_checker_execution(self):
        self.client.login(username="ops_user", password="pass12345")
        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "dispute_refund_submit",
                "case_id": self.case.id,
                "amount": "10.00",
                "currency": "USD",
                "reason": "refund dispute",
            },
        )
        self.assertEqual(resp.status_code, 302)
        refund = DisputeRefundRequest.objects.get(case=self.case)
        self.assertEqual(refund.status, DisputeRefundRequest.STATUS_PENDING)

        self.client.logout()
        self.client.login(username="risk_user", password="pass12345")
        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "dispute_refund_decision",
                "refund_request_id": refund.id,
                "decision": "approve",
                "checker_note": "ok",
            },
        )
        self.assertEqual(resp.status_code, 302)
        refund.refresh_from_db()
        self.case.refresh_from_db()
        self.assertEqual(refund.status, DisputeRefundRequest.STATUS_EXECUTED)
        self.assertEqual(self.case.status, OperationCase.STATUS_RESOLVED)

    def test_settlement_payout_execution(self):
        settlement = MerchantSettlementRecord.objects.create(
            merchant=self.merchant,
            settlement_no="SETTLE-OPS-1",
            currency="USD",
            period_start=self.case.created_at.date(),
            period_end=self.case.created_at.date(),
            gross_amount=Decimal("100"),
            fee_amount=Decimal("1"),
            net_amount=Decimal("99"),
            event_count=1,
            status=MerchantSettlementRecord.STATUS_POSTED,
            created_by=self.admin,
        )
        self.client.login(username="ops_admin", password="pass12345")
        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "settlement_payout_submit",
                "settlement_id": settlement.id,
                "payout_channel": "bank_transfer",
                "destination_account": "ACC-123",
            },
        )
        self.assertEqual(resp.status_code, 302)
        payout = SettlementPayout.objects.get(settlement=settlement)
        self.assertEqual(payout.status, SettlementPayout.STATUS_PENDING)

        self.client.logout()
        self.client.login(username="risk_user", password="pass12345")
        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "settlement_payout_decision",
                "payout_id": payout.id,
                "decision": "settle",
            },
        )
        self.assertEqual(resp.status_code, 302)
        payout.refresh_from_db()
        settlement.refresh_from_db()
        self.assertEqual(payout.status, SettlementPayout.STATUS_SETTLED)
        self.assertEqual(settlement.status, MerchantSettlementRecord.STATUS_PAID)

    def test_reconciliation_run_and_break_resolution(self):
        self.client.login(username="ops_admin", password="pass12345")
        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "reconciliation_run_create",
                "source": "internal_vs_settlement",
                "currency": "USD",
                "period_start": self.case.created_at.date().isoformat(),
                "period_end": self.case.created_at.date().isoformat(),
                "external_count": "10",
                "external_amount": "1000.00",
            },
        )
        self.assertEqual(resp.status_code, 302)
        run = ReconciliationRun.objects.latest("id")
        self.assertEqual(run.status, ReconciliationRun.STATUS_COMPLETED)
        br = ReconciliationBreak.objects.filter(run=run).first()
        self.assertIsNotNone(br)

        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "reconciliation_break_update",
                "break_id": br.id,
                "status": "resolved",
                "note": "balanced manually",
            },
        )
        self.assertEqual(resp.status_code, 302)
        br.refresh_from_db()
        self.assertEqual(br.status, ReconciliationBreak.STATUS_RESOLVED)


class OperationalHardeningTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.admin = User.objects.create_user(username="hard_admin", password="pass12345")
        self.owner = User.objects.create_user(
            username="merchant_owner",
            email="merchant_owner@example.com",
            password="pass12345",
        )
        self.customer = User.objects.create_user(username="hard_customer", password="pass12345")
        assign_roles(self.admin, ["admin"])
        assign_roles(self.owner, ["sales"])
        self.customer.deposit(100)
        self.merchant = Merchant.objects.create(
            code="MHARD1",
            name="Merchant Hard",
            owner=self.owner,
            created_by=self.admin,
            updated_by=self.admin,
        )
        MerchantWalletCapability.objects.create(merchant=self.merchant)
        MerchantLoyaltyProgram.objects.create(merchant=self.merchant)
        MerchantRiskProfile.objects.create(
            merchant=self.merchant,
            daily_txn_limit=1000,
            daily_amount_limit=Decimal("9999999"),
            single_txn_limit=Decimal("999999"),
            reserve_ratio_bps=0,
            require_manual_review_above=Decimal("0"),
            updated_by=self.admin,
        )
        self.case = OperationCase.objects.create(
            case_no="CASE-HARD-1",
            case_type=OperationCase.TYPE_DISPUTE,
            priority=OperationCase.PRIORITY_HIGH,
            title="Hard case",
            customer=self.customer,
            merchant=self.merchant,
            assigned_to=self.admin,
            created_by=self.admin,
        )
        self.credential = MerchantApiCredential.objects.create(
            merchant=self.merchant,
            key_id="mk_hard_1",
            secret_hash="abc123",
            scopes_csv="wallet:read,webhook:write",
            webhook_url="https://merchant.example/callback",
            created_by=self.admin,
            updated_by=self.admin,
        )

    def test_owner_can_open_merchant_portal(self):
        self.client.login(username="merchant_owner", password="pass12345")
        response = self.client.get(reverse("merchant_portal"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Merchant Portal")

    def test_chargeback_create_and_evidence(self):
        self.client.login(username="hard_admin", password="pass12345")
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "chargeback_create",
                "case_id": self.case.id,
                "amount": "9.00",
                "currency": "USD",
                "reason_code": "10.4",
            },
        )
        self.assertEqual(response.status_code, 302)
        cb = ChargebackCase.objects.get(case=self.case)
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "chargeback_evidence_add",
                "chargeback_id": cb.id,
                "document_type": "receipt",
                "document_url": "https://files.example/receipt.pdf",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ChargebackEvidence.objects.filter(chargeback=cb).exists())

    def test_accounting_period_close_blocks_post(self):
        cash = ChartOfAccount.objects.create(
            code="1011",
            name="Cash",
            account_type=ChartOfAccount.TYPE_ASSET,
            currency="USD",
        )
        liability = ChartOfAccount.objects.create(
            code="2011",
            name="Liability",
            account_type=ChartOfAccount.TYPE_LIABILITY,
            currency="USD",
        )
        entry = JournalEntry.objects.create(entry_no="JE-HARD-1", created_by=self.admin, currency="USD")
        JournalLine.objects.create(entry=entry, account=cash, debit="100.00", credit="0")
        JournalLine.objects.create(entry=entry, account=liability, debit="0", credit="100.00")
        today = entry.created_at.date()
        AccountingPeriodClose.objects.create(
            period_start=today,
            period_end=today,
            currency="USD",
            is_closed=True,
            closed_by=self.admin,
            closed_at=entry.created_at,
            created_by=self.admin,
        )
        with self.assertRaises(ValidationError):
            entry.post(self.admin)

    def test_webhook_replay_detection_safe(self):
        self.client.login(username="hard_admin", password="pass12345")
        payload = '{"event":"ok"}'
        import hashlib
        import hmac

        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        signature = hmac.new(
            self.credential.secret_hash.encode("utf-8"),
            f"nonce-1:{payload_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        first = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "merchant_webhook_validate",
                "credential_id": self.credential.id,
                "event_type": "payment.status",
                "nonce": "nonce-1",
                "payload": payload,
                "signature": signature,
            },
        )
        self.assertEqual(first.status_code, 302)
        second = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "merchant_webhook_validate",
                "credential_id": self.credential.id,
                "event_type": "payment.status",
                "nonce": "nonce-1",
                "payload": payload,
                "signature": signature,
            },
        )
        self.assertEqual(second.status_code, 302)
        self.assertEqual(
            MerchantWebhookEvent.objects.filter(credential=self.credential, nonce="nonce-1").count(),
            1,
        )

    def test_access_review_creates_sod_finding(self):
        checker_user = User.objects.create_user(username="sod_user", password="pass12345")
        assign_roles(checker_user, ["finance", "risk"])
        self.client.login(username="hard_admin", password="pass12345")
        response = self.client.post(reverse("operations_center"), {"form_type": "access_review_run"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            AccessReviewRecord.objects.filter(user=checker_user, issue_type="segregation_of_duty").exists()
        )


class OpsWorkflowEscalationCommandTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.actor = User.objects.create_user(username="ops_actor", password="pass12345")
        assign_roles(self.actor, ["admin"])
        self.finance = User.objects.create_user(username="ops_finance", password="pass12345")
        assign_roles(self.finance, ["finance"])
        self.checker = User.objects.create_user(username="ops_checker", password="pass12345")
        assign_roles(self.checker, ["admin"])
        self.customer = User.objects.create_user(username="ops_cmd_customer", password="pass12345")
        self.merchant = Merchant.objects.create(
            code="MESC001",
            name="Escalation Merchant",
            created_by=self.actor,
            updated_by=self.actor,
            owner=self.actor,
        )
        self.cash = ChartOfAccount.objects.create(
            code="9010",
            name="Esc Cash",
            account_type=ChartOfAccount.TYPE_ASSET,
            currency="USD",
        )
        self.liability = ChartOfAccount.objects.create(
            code="9020",
            name="Esc Liability",
            account_type=ChartOfAccount.TYPE_LIABILITY,
            currency="USD",
        )

    def _create_stale_journal_approval(self):
        entry = JournalEntry.objects.create(
            entry_no="JE-ESC-1",
            created_by=self.finance,
            currency="USD",
        )
        JournalLine.objects.create(entry=entry, account=self.cash, debit="50.00", credit="0")
        JournalLine.objects.create(entry=entry, account=self.liability, debit="0", credit="50.00")
        approval = JournalEntryApproval.objects.create(
            entry=entry,
            request_type=JournalEntryApproval.TYPE_POST,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="stale approval",
        )
        JournalEntryApproval.objects.filter(id=approval.id).update(
            created_at=timezone.now() - timezone.timedelta(hours=24)
        )
        return approval

    def _create_stale_settlement_exception(self):
        exception = SettlementException.objects.create(
            reason_code="bank_timeout",
            severity="high",
            status=SettlementException.STATUS_OPEN,
            detail="stale settlement exception",
            created_by=self.actor,
        )
        SettlementException.objects.filter(id=exception.id).update(
            created_at=timezone.now() - timezone.timedelta(hours=30)
        )
        return exception

    def _create_stale_reconciliation_break(self):
        run = ReconciliationRun.objects.create(
            source="internal_vs_settlement",
            run_no="RECON-ESC-1",
            currency="USD",
            period_start=timezone.localdate(),
            period_end=timezone.localdate(),
            created_by=self.actor,
            status=ReconciliationRun.STATUS_COMPLETED,
        )
        recon_break = ReconciliationBreak.objects.create(
            run=run,
            merchant=self.merchant,
            break_category=ReconciliationBreak.CATEGORY_AMOUNT,
            match_status=ReconciliationBreak.MATCH_UNMATCHED,
            expected_amount=Decimal("100.00"),
            actual_amount=Decimal("95.00"),
            delta_amount=Decimal("5.00"),
            status=ReconciliationBreak.STATUS_OPEN,
            created_by=self.actor,
        )
        ReconciliationBreak.objects.filter(id=recon_break.id).update(
            created_at=timezone.now() - timezone.timedelta(hours=36)
        )
        return recon_break

    def test_escalate_ops_work_queue_creates_alerts(self):
        self._create_stale_journal_approval()
        self._create_stale_settlement_exception()
        self._create_stale_reconciliation_break()

        out = io.StringIO()
        call_command(
            "escalate_ops_work_queue",
            actor_username=self.actor.username,
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("journal=1", output)
        self.assertIn("settlement_exceptions=1", output)
        self.assertIn("reconciliation_breaks=1", output)
        self.assertEqual(
            TransactionMonitoringAlert.objects.filter(alert_type="journal_approval_sla").count(),
            1,
        )
        self.assertEqual(
            TransactionMonitoringAlert.objects.filter(alert_type="settlement_exception_sla").count(),
            1,
        )
        self.assertEqual(
            TransactionMonitoringAlert.objects.filter(alert_type="reconciliation_break_sla").count(),
            1,
        )

    def test_escalate_ops_work_queue_dry_run_no_alerts(self):
        self._create_stale_journal_approval()
        self._create_stale_settlement_exception()
        self._create_stale_reconciliation_break()

        out = io.StringIO()
        call_command(
            "escalate_ops_work_queue",
            actor_username=self.actor.username,
            dry_run=True,
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("dry_run=True", output)
        self.assertEqual(TransactionMonitoringAlert.objects.count(), 0)

    def test_escalate_ops_work_queue_is_idempotent_for_open_alerts(self):
        self._create_stale_journal_approval()
        self._create_stale_settlement_exception()
        self._create_stale_reconciliation_break()

        call_command("escalate_ops_work_queue", actor_username=self.actor.username, stdout=io.StringIO())
        call_command("escalate_ops_work_queue", actor_username=self.actor.username, stdout=io.StringIO())
        self.assertEqual(
            TransactionMonitoringAlert.objects.filter(alert_type="journal_approval_sla").count(),
            1,
        )
        self.assertEqual(
            TransactionMonitoringAlert.objects.filter(alert_type="settlement_exception_sla").count(),
            1,
        )
        self.assertEqual(
            TransactionMonitoringAlert.objects.filter(alert_type="reconciliation_break_sla").count(),
            1,
        )


class MetricsOpsVisibilityTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.actor = User.objects.create_user(username="metrics_actor", password="pass12345")
        assign_roles(self.actor, ["admin"])
        self.finance = User.objects.create_user(username="metrics_finance", password="pass12345")
        assign_roles(self.finance, ["finance"])
        self.cash = ChartOfAccount.objects.create(
            code="9030",
            name="Metrics Cash",
            account_type=ChartOfAccount.TYPE_ASSET,
            currency="USD",
        )
        self.liability = ChartOfAccount.objects.create(
            code="9040",
            name="Metrics Liability",
            account_type=ChartOfAccount.TYPE_LIABILITY,
            currency="USD",
        )
        entry = JournalEntry.objects.create(entry_no="JE-MET-1", created_by=self.finance, currency="USD")
        JournalLine.objects.create(entry=entry, account=self.cash, debit="11.00", credit="0")
        JournalLine.objects.create(entry=entry, account=self.liability, debit="0", credit="11.00")
        approval = JournalEntryApproval.objects.create(
            entry=entry,
            request_type=JournalEntryApproval.TYPE_POST,
            status=JournalEntryApproval.STATUS_PENDING,
            maker=self.finance,
            reason="metrics pending",
        )
        JournalEntryApproval.objects.filter(id=approval.id).update(
            created_at=timezone.now() - timezone.timedelta(hours=24)
        )
        SettlementException.objects.create(
            reason_code="ops_metrics",
            severity="medium",
            status=SettlementException.STATUS_OPEN,
            detail="metrics exception",
            created_by=self.actor,
        )

    @override_settings(JOURNAL_APPROVAL_SLA_HOURS=8)
    def test_metrics_contains_accounting_ops_gauges(self):
        response = self.client.get(reverse("metrics"))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode("utf-8")
        self.assertIn("wallet_ops_settlement_exceptions_open_count", body)
        self.assertIn("wallet_ops_journal_approvals_pending_count", body)
        self.assertIn("wallet_ops_journal_approvals_sla_breach_count", body)
