from decimal import Decimal
from datetime import date
import hashlib
import hmac
import io
import json
import time
from unittest.mock import patch

from django.contrib.auth.hashers import make_password
from django.core.cache import cache
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
    BusinessDocument,
    ChartOfAccount,
    ChargebackCase,
    ChargebackEvidence,
    CustomerCIF,
    CustomerClassUpgradeRequest,
    DisputeRefundRequest,
    FxRate,
    JournalEntry,
    JournalEntryApproval,
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
    OperationCaseNote,
    OperationSetting,
    ReconciliationBreak,
    ReconciliationRun,
    ServiceClassPolicy,
    SettlementException,
    SettlementPayout,
    Tenant,
    TenantBillingEvent,
    TenantBillingInboundEvent,
    TenantBillingWebhook,
    TenantInvoice,
    TenantOnboardingInvite,
    TenantSubscription,
    TenantUsageDaily,
    TransactionMonitoringAlert,
    TreasuryAccount,
    TreasuryTransferRequest,
    User,
    FLOW_C2B,
    WALLET_TYPE_CUSTOMER,
)
from .rbac import assign_roles, seed_role_groups
from .saas import claim_pending_onboarding_invite_for_user, record_tenant_usage


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


@override_settings(MULTITENANCY_ENABLED=True, MULTITENANCY_DEFAULT_TENANT_CODE="tenant_a")
class MultiTenantIsolationTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.tenant_a = Tenant.objects.create(code="tenant_a", name="Tenant A")
        self.tenant_b = Tenant.objects.create(code="tenant_b", name="Tenant B")
        self.admin_a = User.objects.create_user(username="tenant_admin_a", password="pass12345", tenant=self.tenant_a)
        self.admin_b = User.objects.create_user(username="tenant_admin_b", password="pass12345", tenant=self.tenant_b)
        self.user_a = User.objects.create_user(
            username="tenant_user_a",
            password="pass12345",
            tenant=self.tenant_a,
        )
        assign_roles(self.admin_a, ["admin"])
        assign_roles(self.admin_b, ["admin"])
        self.merchant_b = Merchant.objects.create(
            tenant=self.tenant_b,
            code="MT-B-001",
            name="Merchant B",
            created_by=self.admin_b,
            updated_by=self.admin_b,
            owner=self.admin_b,
        )
        self.user_b = User.objects.create_user(
            username="tenant_user_b",
            password="pass12345",
            tenant=self.tenant_b,
        )
        prefs = self.user_b.mobile_preferences if isinstance(self.user_b.mobile_preferences, dict) else {}
        prefs["transaction_pin_hash"] = make_password("1234")
        self.user_b.mobile_preferences = prefs
        self.user_b.save(update_fields=["mobile_preferences"])
        self.case_b = OperationCase.objects.create(
            case_no="MT-CASE-B-1",
            case_type=OperationCase.TYPE_DISPUTE,
            priority=OperationCase.PRIORITY_MEDIUM,
            status=OperationCase.STATUS_OPEN,
            title="Tenant B Case",
            customer=self.user_b,
            merchant=self.merchant_b,
            created_by=self.admin_b,
        )
        self.case_a = OperationCase.objects.create(
            case_no="MT-CASE-A-1",
            case_type=OperationCase.TYPE_COMPLAINT,
            priority=OperationCase.PRIORITY_MEDIUM,
            status=OperationCase.STATUS_OPEN,
            title="Tenant A Case",
            customer=self.user_a,
            merchant=None,
            created_by=self.admin_a,
        )
        self.refund_b = DisputeRefundRequest.objects.create(
            case=self.case_b,
            merchant=self.merchant_b,
            customer=self.user_b,
            amount=Decimal("5.00"),
            currency="USD",
            reason="tenant b refund",
            maker=self.admin_b,
            status=DisputeRefundRequest.STATUS_PENDING,
        )

    def test_operations_center_blocks_cross_tenant_merchant_mutation(self):
        self.client.login(username="tenant_admin_a", password="pass12345")
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "merchant_update",
                "merchant_id": self.merchant_b.id,
                "status": Merchant.STATUS_SUSPENDED,
            },
            HTTP_X_TENANT_CODE="tenant_a",
        )
        self.assertEqual(response.status_code, 200)
        self.merchant_b.refresh_from_db()
        self.assertEqual(self.merchant_b.status, Merchant.STATUS_ACTIVE)

    def test_playground_action_hides_cross_tenant_user(self):
        self.client.login(username="tenant_admin_a", password="pass12345")
        response = self.client.post(
            reverse("mobile_portal:playground_assistant_action"),
            data=json.dumps(
                {
                    "action": "deposit",
                    "amount": "10",
                    "currency": "USD",
                    "from_username": self.user_b.username,
                    "execute": True,
                    "pin": "1234",
                }
            ),
            content_type="application/json",
            HTTP_X_TENANT_CODE="tenant_a",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "user_not_found")

    def test_case_detail_blocks_cross_tenant_case(self):
        self.client.login(username="tenant_admin_a", password="pass12345")
        response = self.client.get(
            reverse("case_detail", kwargs={"case_id": self.case_b.id}),
            HTTP_X_TENANT_CODE="tenant_a",
        )
        self.assertEqual(response.status_code, 404)

    def test_operations_reports_scopes_kpis_by_tenant(self):
        self.client.login(username="tenant_admin_a", password="pass12345")
        response = self.client.get(reverse("operations_reports"), HTTP_X_TENANT_CODE="tenant_a")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["kpis"]["cases_open"], 1)

    def test_ops_work_queue_hides_cross_tenant_pending_items(self):
        self.client.login(username="tenant_admin_a", password="pass12345")
        response = self.client.get(reverse("ops_work_queue"), HTTP_X_TENANT_CODE="tenant_a")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, f"RFD-{self.refund_b.id}")

    def test_documents_center_hides_cross_tenant_documents(self):
        BusinessDocument.objects.create(
            source_module=BusinessDocument.SOURCE_CASE,
            title="Tenant B Private Doc",
            document_type="evidence",
            external_url="https://example.com/tenant-b-doc.pdf",
            is_internal=True,
            case=self.case_b,
            merchant=self.merchant_b,
            customer=self.user_b,
            uploaded_by=self.admin_b,
        )
        self.client.login(username="tenant_admin_a", password="pass12345")
        response = self.client.get(reverse("documents_center"), HTTP_X_TENANT_CODE="tenant_a")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Tenant B Private Doc")

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
        User.objects.create_user(username="outsider_acc", password="pass12345")
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

    def test_wallet_management_action_matrix_blocks_disallowed_action(self):
        settings_row = OperationSetting.get_solo()
        settings_row.action_visibility_rules = {
            "wallet.toggle_freeze": ["super_admin"],
        }
        settings_row.save(update_fields=["action_visibility_rules", "updated_at"])

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
        self.assertEqual(response.status_code, 200)
        self.user.get_wallet("default").refresh_from_db()
        self.assertFalse(self.user.get_wallet("default").is_frozen)


class MobileSelfOnboardingApiTests(TestCase):
    def setUp(self):
        seed_role_groups()
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            username="mobile_user",
            email="mobile_user@example.com",
            password="pass12345",
        )
        self.default_policy = ServiceClassPolicy.objects.create(
            entity_type=ServiceClassPolicy.ENTITY_CUSTOMER,
            code="Z",
            name="Starter",
            description="Default low-risk class for self onboarding",
            is_active=True,
            allow_deposit=True,
            allow_withdraw=False,
            allow_transfer=False,
            allow_fx=False,
        )

    def test_mobile_bootstrap_requires_authentication(self):
        response = self.client.get(reverse("mobile_portal:mobile_bootstrap"))
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["ok"])

    def test_mobile_self_onboard_creates_cif_and_wallets(self):
        self.client.login(username="mobile_user", password="pass12345")
        response = self.client.post(
            reverse("mobile_portal:mobile_self_onboard"),
            data='{"legal_name":"Mobile User","mobile_no":"+85512345678","preferred_currency":"EUR","wallet_currencies":["USD","EUR"]}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["data"]["created"])

        self.user.refresh_from_db()
        self.assertEqual(self.user.wallet_type, WALLET_TYPE_CUSTOMER)
        cif = CustomerCIF.objects.get(user=self.user)
        self.assertEqual(cif.legal_name, "Mobile User")
        self.assertEqual(cif.service_class_id, self.default_policy.id)
        self.assertEqual(cif.status, CustomerCIF.STATUS_PENDING_KYC)
        self.assertTrue(self.user.get_wallet("default").is_frozen)

        bootstrap = self.client.get(reverse("mobile_portal:mobile_bootstrap"))
        self.assertEqual(bootstrap.status_code, 200)
        bootstrap_payload = bootstrap.json()
        self.assertTrue(bootstrap_payload["data"]["onboarding"]["is_completed"])
        self.assertEqual(bootstrap_payload["data"]["onboarding"]["status"], CustomerCIF.STATUS_PENDING_KYC)
        wallet_currencies = {w["currency"] for w in bootstrap_payload["data"]["wallets"]}
        self.assertIn("USD", wallet_currencies)
        self.assertIn("EUR", wallet_currencies)

    def test_mobile_profile_get_and_update(self):
        self.client.login(username="mobile_user", password="pass12345")
        self.client.post(
            reverse("mobile_portal:mobile_self_onboard"),
            data='{"legal_name":"Mobile User","mobile_no":"+85512345678","preferred_currency":"USD"}',
            content_type="application/json",
        )

        profile_get = self.client.get(reverse("mobile_portal:mobile_profile"))
        self.assertEqual(profile_get.status_code, 200)
        profile_payload = profile_get.json()
        self.assertTrue(profile_payload["ok"])
        self.assertEqual(profile_payload["data"]["cif"]["legal_name"], "Mobile User")

        profile_update = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data='{"first_name":"Mobile","last_name":"Tester","legal_name":"Mobile Tester","mobile_no":"+855999000","profile_picture_url":"https://cdn.example.com/avatar.png","preferences":{"language":"km","timezone":"Asia/Phnom_Penh","theme":"dark","preferred_currency":"KHR","notifications":{"push":true,"email":false,"sms":true}}}',
            content_type="application/json",
        )
        self.assertEqual(profile_update.status_code, 200)
        update_payload = profile_update.json()
        self.assertTrue(update_payload["ok"])
        self.assertEqual(update_payload["data"]["user"]["first_name"], "Mobile")
        self.assertEqual(
            update_payload["data"]["user"]["profile_picture_url"],
            "https://cdn.example.com/avatar.png",
        )
        self.assertEqual(update_payload["data"]["user"]["preferences"]["language"], "km")
        self.assertEqual(update_payload["data"]["cif"]["legal_name"], "Mobile Tester")

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Mobile")
        self.assertEqual(self.user.mobile_preferences["preferred_currency"], "KHR")
        cif = CustomerCIF.objects.get(user=self.user)
        self.assertEqual(cif.mobile_no, "+855999000")

    def test_mobile_profile_update_requires_onboarding(self):
        self.client.login(username="mobile_user", password="pass12345")
        response = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data='{"first_name":"No","last_name":"CIF","legal_name":"No CIF"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 409)
        body = response.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], "onboarding_required")

    def test_mobile_personalization_data_points(self):
        self.client.login(username="mobile_user", password="pass12345")
        self.client.post(
            reverse("mobile_portal:mobile_self_onboard"),
            data='{"legal_name":"Mobile User","mobile_no":"+85512345678","preferred_currency":"USD"}',
            content_type="application/json",
        )
        update_profile = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data='{"profile_picture_url":"https://cdn.example.com/u.png","preferences":{"language":"en","timezone":"Asia/Phnom_Penh","theme":"system","preferred_currency":"USD"}}',
            content_type="application/json",
        )
        self.assertEqual(update_profile.status_code, 200)

        signal_response = self.client.post(
            reverse("mobile_portal:mobile_personalization_signals"),
            data='{"data_points":{"last_screen":"wallet_home","preferred_entry_point":"scan_pay"}}',
            content_type="application/json",
        )
        self.assertEqual(signal_response.status_code, 200)
        self.assertTrue(signal_response.json()["ok"])
        self.assertEqual(
            signal_response.json()["data"]["data_points"]["last_screen"],
            "wallet_home",
        )

        personalization_response = self.client.get(reverse("mobile_portal:mobile_personalization"))
        self.assertEqual(personalization_response.status_code, 200)
        payload = personalization_response.json()
        self.assertTrue(payload["ok"])
        self.assertIn("native_mfe", payload["data"])
        self.assertIn("segments", payload["data"])
        self.assertEqual(
            payload["data"]["data_points"]["preferred_entry_point"],
            "scan_pay",
        )

    def test_mobile_assistant_chat_requires_message(self):
        self.client.login(username="mobile_user", password="pass12345")
        response = self.client.post(
            reverse("mobile_portal:mobile_assistant_chat"),
            data="{}",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["ok"])
        self.assertEqual(response.json()["error"]["code"], "message_required")

    @patch("wallets_demo.views_mobile._openai_assistant_fallback")
    def test_mobile_assistant_chat_returns_transaction_action_proposal(self, openai_fallback_mock):
        self.client.login(username="mobile_user", password="pass12345")
        openai_fallback_mock.return_value = {
            "enabled": True,
            "status": "ok",
            "reply": "I can help you transfer funds.",
            "suggested_actions": ["transfer_funds"],
        }
        response = self.client.post(
            reverse("mobile_portal:mobile_assistant_chat"),
            data=json.dumps({"message": "Please transfer 25 USD to alice"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        assistant = body["data"]["assistant"]
        self.assertEqual(assistant["status"], "ok")
        proposal = assistant.get("action_proposal")
        self.assertIsInstance(proposal, dict)
        self.assertEqual(proposal["kind"], "transaction_request")
        self.assertEqual(proposal["prefill"]["action"], "transfer")
        self.assertEqual(proposal["prefill"]["currency"], "USD")
        self.assertEqual(proposal["prefill"]["amount"], "25")

    def test_mobile_profile_pin_rotation_requires_current_pin(self):
        self.client.login(username="mobile_user", password="pass12345")
        self.client.post(
            reverse("mobile_portal:mobile_self_onboard"),
            data='{"legal_name":"Mobile User","mobile_no":"+85512345678","preferred_currency":"USD"}',
            content_type="application/json",
        )
        set_pin = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data=json.dumps({"transaction_pin": "2468", "transaction_pin_confirm": "2468"}),
            content_type="application/json",
        )
        self.assertEqual(set_pin.status_code, 200)

        missing_current = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data=json.dumps({"transaction_pin": "8642", "transaction_pin_confirm": "8642"}),
            content_type="application/json",
        )
        self.assertEqual(missing_current.status_code, 403)
        self.assertEqual(missing_current.json()["error"]["code"], "current_pin_required")

        wrong_current = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data=json.dumps(
                {
                    "current_transaction_pin": "0000",
                    "transaction_pin": "8642",
                    "transaction_pin_confirm": "8642",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(wrong_current.status_code, 403)
        self.assertEqual(wrong_current.json()["error"]["code"], "current_pin_invalid")

        ok_rotate = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data=json.dumps(
                {
                    "current_transaction_pin": "2468",
                    "transaction_pin": "8642",
                    "transaction_pin_confirm": "8642",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(ok_rotate.status_code, 200)
        self.assertTrue(ok_rotate.json()["ok"])

    def test_mobile_profile_pin_rotation_lockout_after_failed_attempts(self):
        self.client.login(username="mobile_user", password="pass12345")
        self.client.post(
            reverse("mobile_portal:mobile_self_onboard"),
            data='{"legal_name":"Mobile User","mobile_no":"+85512345678","preferred_currency":"USD"}',
            content_type="application/json",
        )
        self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data=json.dumps({"transaction_pin": "2468", "transaction_pin_confirm": "2468"}),
            content_type="application/json",
        )

        for _ in range(5):
            self.client.post(
                reverse("mobile_portal:mobile_profile"),
                data=json.dumps(
                    {
                        "current_transaction_pin": "0000",
                        "transaction_pin": "8642",
                        "transaction_pin_confirm": "8642",
                    }
                ),
                content_type="application/json",
            )
        locked = self.client.post(
            reverse("mobile_portal:mobile_profile"),
            data=json.dumps(
                {
                    "current_transaction_pin": "2468",
                    "transaction_pin": "9753",
                    "transaction_pin_confirm": "9753",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(locked.status_code, 429)
        self.assertEqual(locked.json()["error"]["code"], "pin_setup_locked")
        self.assertIn("retry_after_seconds", locked.json()["error"].get("metadata", {}))


class MobileNativeLabPageTests(TestCase):
    def setUp(self):
        seed_role_groups()
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            username="native_lab_user",
            email="native_lab_user@example.com",
            password="pass12345",
        )
        assign_roles(self.user, ["operation"])
        self.target_user = User.objects.create_user(
            username="native_lab_target",
            email="native_lab_target@example.com",
            password="pass12345",
            first_name="Target",
            last_name="User",
        )
        CustomerCIF.objects.create(
            cif_no="CIF-LAB-TARGET",
            user=self.target_user,
            legal_name="Target User",
            mobile_no="+85510020001",
            email=self.target_user.email,
            created_by=self.user,
        )

    def test_mobile_native_lab_requires_auth(self):
        response = self.client.get(reverse("mobile_portal:home"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_mobile_native_lab_renders_for_authenticated_user(self):
        self.client.login(username="native_lab_user", password="pass12345")
        response = self.client.get(reverse("mobile_portal:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Mobile Service Playground")
        self.assertContains(response, "/mobile/v1")

    def test_mobile_native_lab_forbidden_for_non_backoffice_role(self):
        User.objects.create_user(
            username="native_lab_outsider",
            email="native_lab_outsider@example.com",
            password="pass12345",
        )
        self.client.login(username="native_lab_outsider", password="pass12345")
        response = self.client.get(reverse("mobile_portal:home"))
        self.assertEqual(response.status_code, 403)

    def test_mobile_playground_can_impersonate_mobile_profile_user(self):
        self.client.login(username="native_lab_user", password="pass12345")
        set_response = self.client.post(
            reverse("mobile_portal:playground_impersonation"),
            data=json.dumps({"username": "native_lab_target"}),
            content_type="application/json",
        )
        self.assertEqual(set_response.status_code, 200)
        self.assertTrue(set_response.json()["ok"])
        self.assertEqual(
            set_response.json()["data"]["effective_user"]["username"],
            "native_lab_target",
        )

        profile_response = self.client.get(reverse("mobile_portal:mobile_profile"))
        self.assertEqual(profile_response.status_code, 200)
        profile_data = profile_response.json()["data"]["user"]
        self.assertEqual(profile_data["username"], "native_lab_target")

        clear_response = self.client.delete(reverse("mobile_portal:playground_impersonation"))
        self.assertEqual(clear_response.status_code, 200)
        self.assertFalse(clear_response.json()["data"]["impersonation_enabled"])

    def test_mobile_playground_transaction_commit_requires_valid_pin(self):
        prefs = self.target_user.mobile_preferences if isinstance(self.target_user.mobile_preferences, dict) else {}
        prefs["transaction_pin_hash"] = make_password("1234")
        self.target_user.mobile_preferences = prefs
        self.target_user.save(update_fields=["mobile_preferences"])

        self.client.login(username="native_lab_user", password="pass12345")
        no_pin_response = self.client.post(
            reverse("mobile_portal:playground_assistant_action"),
            data=json.dumps(
                {
                    "action": "deposit",
                    "amount": "10",
                    "currency": "USD",
                    "from_username": "native_lab_target",
                    "execute": True,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(no_pin_response.status_code, 403)
        self.assertEqual(no_pin_response.json()["error"]["code"], "pin_required")

        wrong_pin_response = self.client.post(
            reverse("mobile_portal:playground_assistant_action"),
            data=json.dumps(
                {
                    "action": "deposit",
                    "amount": "10",
                    "currency": "USD",
                    "from_username": "native_lab_target",
                    "execute": True,
                    "pin": "0000",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(wrong_pin_response.status_code, 403)
        self.assertEqual(wrong_pin_response.json()["error"]["code"], "pin_invalid")

        ok_response = self.client.post(
            reverse("mobile_portal:playground_assistant_action"),
            data=json.dumps(
                {
                    "action": "deposit",
                    "amount": "10",
                    "currency": "USD",
                    "from_username": "native_lab_target",
                    "execute": True,
                    "pin": "1234",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(ok_response.status_code, 200)
        self.assertTrue(ok_response.json()["data"]["allowed"])
        self.assertTrue(ok_response.json()["data"]["execute"])

    def test_mobile_playground_transaction_commit_pin_lockout(self):
        prefs = self.target_user.mobile_preferences if isinstance(self.target_user.mobile_preferences, dict) else {}
        prefs["transaction_pin_hash"] = make_password("1234")
        self.target_user.mobile_preferences = prefs
        self.target_user.save(update_fields=["mobile_preferences"])

        self.client.login(username="native_lab_user", password="pass12345")
        for _ in range(5):
            self.client.post(
                reverse("mobile_portal:playground_assistant_action"),
                data=json.dumps(
                    {
                        "action": "deposit",
                        "amount": "10",
                        "currency": "USD",
                        "from_username": "native_lab_target",
                        "execute": True,
                        "pin": "0000",
                    }
                ),
                content_type="application/json",
            )

        locked_response = self.client.post(
            reverse("mobile_portal:playground_assistant_action"),
            data=json.dumps(
                {
                    "action": "deposit",
                    "amount": "10",
                    "currency": "USD",
                    "from_username": "native_lab_target",
                    "execute": True,
                    "pin": "1234",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(locked_response.status_code, 429)
        body = locked_response.json()
        self.assertEqual(body["error"]["code"], "pin_locked")
        self.assertIn("retry_after_seconds", body["error"].get("metadata", {}))


class PolicyHubUpgradeWorkflowTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.maker = User.objects.create_user(username="policy_maker", password="pass12345")
        self.checker = User.objects.create_user(username="policy_checker", password="pass12345")
        self.customer = User.objects.create_user(
            username="policy_customer",
            email="policy_customer@example.com",
            password="pass12345",
        )
        assign_roles(self.maker, ["operation"])
        assign_roles(self.checker, ["risk"])

        self.policy_z = ServiceClassPolicy.objects.create(
            entity_type=ServiceClassPolicy.ENTITY_CUSTOMER,
            code="Z",
            name="Starter",
            is_active=True,
            allow_deposit=True,
            allow_withdraw=False,
            allow_transfer=False,
            allow_fx=False,
            daily_txn_count_limit=10,
            daily_amount_limit=Decimal("1000"),
            monthly_txn_count_limit=100,
            monthly_amount_limit=Decimal("10000"),
        )
        self.policy_a = ServiceClassPolicy.objects.create(
            entity_type=ServiceClassPolicy.ENTITY_CUSTOMER,
            code="A",
            name="Premium",
            is_active=True,
            allow_deposit=True,
            allow_withdraw=True,
            allow_transfer=True,
            allow_fx=True,
        )
        self.cif = CustomerCIF.objects.create(
            cif_no="CIF-POLICY-1",
            user=self.customer,
            legal_name="Policy Customer",
            mobile_no="+85510001000",
            email=self.customer.email,
            service_class=self.policy_z,
            status=CustomerCIF.STATUS_PENDING_KYC,
            created_by=self.maker,
        )
        self.customer.freeze_wallet("default")

    def test_policy_upgrade_request_and_checker_approval_activates_cif(self):
        self.client.login(username="policy_maker", password="pass12345")
        response = self.client.post(
            reverse("policy_hub"),
            {
                "form_type": "policy_upgrade_customer_request",
                "cif_id": self.cif.id,
                "target_policy_id": self.policy_a.id,
                "maker_note": "KYC docs completed",
            },
        )
        self.assertEqual(response.status_code, 302)
        req = CustomerClassUpgradeRequest.objects.get()
        self.assertEqual(req.status, CustomerClassUpgradeRequest.STATUS_PENDING)

        self.client.login(username="policy_checker", password="pass12345")
        response = self.client.post(
            reverse("policy_hub"),
            {
                "form_type": "policy_upgrade_customer_decision",
                "request_id": req.id,
                "decision": "approve",
                "checker_note": "Approved after verification",
            },
        )
        self.assertEqual(response.status_code, 302)
        req.refresh_from_db()
        self.cif.refresh_from_db()
        self.customer.refresh_from_db()
        self.assertEqual(req.status, CustomerClassUpgradeRequest.STATUS_APPROVED)
        self.assertEqual(self.cif.service_class_id, self.policy_a.id)
        self.assertEqual(self.cif.status, CustomerCIF.STATUS_ACTIVE)
        self.assertFalse(self.customer.get_wallet("default").is_frozen)


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

        checker_admin = User.objects.create_user(
            username="ops_admin_checker",
            password="pass12345",
        )
        assign_roles(checker_admin, ["admin"])
        self.client.logout()
        self.client.login(username="ops_admin_checker", password="pass12345")
        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "settlement_payout_decision",
                "payout_id": payout.id,
                "decision": "settle",
                "checker_note": "settled after bank confirmation",
            },
        )
        self.assertEqual(resp.status_code, 302)
        payout.refresh_from_db()
        settlement.refresh_from_db()
        self.assertEqual(payout.status, SettlementPayout.STATUS_SETTLED)
        self.assertEqual(settlement.status, MerchantSettlementRecord.STATUS_PAID)

    def test_payout_decision_rejects_maker_checker_same_user(self):
        settlement = MerchantSettlementRecord.objects.create(
            merchant=self.merchant,
            settlement_no="SETTLE-OPS-2",
            currency="USD",
            period_start=self.case.created_at.date(),
            period_end=self.case.created_at.date(),
            gross_amount=Decimal("120"),
            fee_amount=Decimal("2"),
            net_amount=Decimal("118"),
            event_count=1,
            status=MerchantSettlementRecord.STATUS_POSTED,
            created_by=self.admin,
        )
        self.client.login(username="ops_admin", password="pass12345")
        submit_resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "settlement_payout_submit",
                "settlement_id": settlement.id,
                "payout_channel": "bank_transfer",
                "destination_account": "ACC-RISK",
            },
        )
        self.assertEqual(submit_resp.status_code, 302)
        payout = SettlementPayout.objects.get(settlement=settlement)
        self.assertEqual(payout.initiated_by, self.admin)

        decide_resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "settlement_payout_decision",
                "payout_id": payout.id,
                "decision": "send",
                "checker_note": "self-check should fail",
            },
        )
        self.assertEqual(decide_resp.status_code, 200)
        payout.refresh_from_db()
        self.assertEqual(payout.status, SettlementPayout.STATUS_PENDING)

    def test_case_resolution_requires_note(self):
        self.client.login(username="ops_user", password="pass12345")
        resp = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "case_update",
                "case_id": self.case.id,
                "status": OperationCase.STATUS_RESOLVED,
                "note": "",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.case.refresh_from_db()
        self.assertNotEqual(self.case.status, OperationCase.STATUS_RESOLVED)

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


@override_settings(MULTITENANCY_ENABLED=True, MULTITENANCY_DEFAULT_TENANT_CODE="default")
class OpenApiMerchantIntegrationTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.tenant, _ = Tenant.objects.get_or_create(code="default", defaults={"name": "Default"})
        self.admin = User.objects.create_user(username="open_admin", password="pass12345", tenant=self.tenant)
        self.owner = User.objects.create_user(username="open_owner", password="pass12345", tenant=self.tenant)
        self.customer = User.objects.create_user(username="open_customer", password="pass12345", tenant=self.tenant)
        assign_roles(self.admin, ["admin"])
        self.customer.deposit(Decimal("200.00"))
        self.merchant = Merchant.objects.create(
            code="MOPEN01",
            name="Open API Merchant",
            tenant=self.tenant,
            owner=self.owner,
            created_by=self.admin,
            updated_by=self.admin,
        )
        MerchantWalletCapability.objects.create(merchant=self.merchant, supports_c2b=True, supports_b2c=True)
        MerchantRiskProfile.objects.create(
            merchant=self.merchant,
            daily_txn_limit=10000,
            daily_amount_limit=Decimal("9999999"),
            single_txn_limit=Decimal("999999"),
            reserve_ratio_bps=0,
            require_manual_review_above=Decimal("0"),
            updated_by=self.admin,
        )
        self.credential = MerchantApiCredential.objects.create(
            merchant=self.merchant,
            key_id="mk_open_1",
            secret_hash="open-secret",
            scopes_csv="wallet:read,payment:write,payout:write",
            sandbox_enabled=True,
            live_enabled=False,
            is_active=True,
            created_by=self.admin,
            updated_by=self.admin,
        )

    def _signed_headers(self, payload: dict | None = None, *, environment: str = "sandbox", nonce: str | None = None):
        payload = payload or {}
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ts = int(time.time())
        used_nonce = nonce or f"nonce-{ts}"
        body_hash = hashlib.sha256(raw).hexdigest()
        signature = hmac.new(
            self.credential.secret_hash.encode("utf-8"),
            f"{ts}:{used_nonce}:{body_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return (
            raw,
            {
                "HTTP_X_API_KEY": self.credential.key_id,
                "HTTP_X_NONCE": used_nonce,
                "HTTP_X_TIMESTAMP": str(ts),
                "HTTP_X_SIGNATURE": signature,
                "HTTP_X_TENANT_CODE": self.tenant.code,
                "HTTP_X_ENVIRONMENT": environment,
            },
        )

    def test_open_api_docs_endpoint(self):
        response = self.client.get(reverse("open_api:docs"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/open-api/v1/payments/c2b/")

    def test_sandbox_c2b_does_not_mutate_live_wallets(self):
        payload = {
            "customer_username": self.customer.username,
            "amount": "12.00",
            "currency": "USD",
            "reference": "SBOX-001",
        }
        raw, headers = self._signed_headers(payload, environment="sandbox")
        response = self.client.post(
            reverse("open_api:sandbox_payment_c2b"),
            data=raw,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["status"], "sandbox_simulated")
        self.assertEqual(MerchantCashflowEvent.objects.count(), 0)

    def test_live_mode_is_blocked_when_not_enabled(self):
        payload = {
            "customer_username": self.customer.username,
            "amount": "10.00",
            "currency": "USD",
            "reference": "LIVE-BLOCK",
        }
        raw, headers = self._signed_headers(payload, environment="live")
        response = self.client.post(
            reverse("open_api:payment_c2b"),
            data=raw,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "forbidden")

    def test_live_c2b_executes_when_enabled(self):
        self.credential.live_enabled = True
        self.credential.save(update_fields=["live_enabled", "updated_at"])
        payload = {
            "customer_username": self.customer.username,
            "amount": "15.00",
            "currency": "USD",
            "reference": "LIVE-C2B-1",
            "note": "integration run",
        }
        raw, headers = self._signed_headers(payload, environment="live")
        response = self.client.post(
            reverse("open_api:payment_c2b"),
            data=raw,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 200)
        event = MerchantCashflowEvent.objects.get(reference="LIVE-C2B-1")
        self.assertEqual(event.flow_type, FLOW_C2B)

    def test_open_api_nonce_replay_is_blocked(self):
        payload = {
            "amount": "9.00",
            "currency": "USD",
        }
        raw, headers = self._signed_headers(payload, environment="sandbox", nonce="replay-1")
        first = self.client.post(
            reverse("open_api:sandbox_payout_b2c"),
            data=raw,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(first.status_code, 200)
        second = self.client.post(
            reverse("open_api:sandbox_payout_b2c"),
            data=raw,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(second.status_code, 403)
        self.assertEqual(second.json()["error"]["code"], "forbidden")

    def test_live_c2b_blocked_by_tenant_quota(self):
        self.credential.live_enabled = True
        self.credential.save(update_fields=["live_enabled", "updated_at"])
        subscription, _ = TenantSubscription.objects.get_or_create(
            tenant=self.tenant,
            defaults={"plan_code": "starter", "status": TenantSubscription.STATUS_ACTIVE},
        )
        subscription.hard_limit_monthly_txn = 1
        subscription.hard_limit_enforced = True
        subscription.save(update_fields=["hard_limit_monthly_txn", "hard_limit_enforced", "updated_at"])
        TenantUsageDaily.objects.create(
            tenant=self.tenant,
            usage_date=timezone.localdate(),
            metric_code="wallet.transfer.success",
            quantity=1,
            amount=Decimal("10.00"),
        )
        payload = {
            "customer_username": self.customer.username,
            "amount": "5.00",
            "currency": "USD",
            "reference": "LIVE-QUOTA-BLOCK",
        }
        raw, headers = self._signed_headers(payload, environment="live")
        response = self.client.post(
            reverse("open_api:payment_c2b"),
            data=raw,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "validation_error")


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


class OperationCaseSLAWorkflowTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.ops = User.objects.create_user(username="case_ops", password="pass12345")
        self.actor = User.objects.create_user(username="case_actor", password="pass12345")
        self.customer = User.objects.create_user(username="case_customer", password="pass12345")
        assign_roles(self.ops, ["operation"])
        assign_roles(self.actor, ["admin"])

    def test_case_create_sets_sla_due_at_from_hours(self):
        self.client.login(username="case_ops", password="pass12345")
        before = timezone.now()
        response = self.client.post(
            reverse("operations_center"),
            {
                "form_type": "case_create",
                "case_type": OperationCase.TYPE_COMPLAINT,
                "case_priority": OperationCase.PRIORITY_MEDIUM,
                "case_customer_id": self.customer.id,
                "case_title": "SLA create test",
                "case_description": "check sla",
                "sla_hours": "4",
            },
        )
        self.assertEqual(response.status_code, 302)
        case = OperationCase.objects.latest("id")
        self.assertIsNotNone(case.sla_due_at)
        self.assertGreaterEqual(case.sla_due_at, before + timezone.timedelta(hours=3, minutes=59))

    def test_escalate_operation_cases_command(self):
        case = OperationCase.objects.create(
            case_no="CASE-SLA-1",
            case_type=OperationCase.TYPE_COMPLAINT,
            priority=OperationCase.PRIORITY_HIGH,
            status=OperationCase.STATUS_OPEN,
            title="Overdue case",
            customer=self.customer,
            created_by=self.ops,
            assigned_to=self.ops,
            sla_due_at=timezone.now() - timezone.timedelta(hours=2),
        )
        out = io.StringIO()
        call_command(
            "escalate_operation_cases",
            actor_username=self.actor.username,
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("Escalated operation cases: 1", output)
        case.refresh_from_db()
        self.assertEqual(case.status, OperationCase.STATUS_ESCALATED)
        self.assertTrue(
            OperationCaseNote.objects.filter(case=case, note__icontains="Auto-escalated case").exists()
        )
        self.assertTrue(
            TransactionMonitoringAlert.objects.filter(alert_type="case_sla_breach", case=case).exists()
        )

    def test_escalate_operation_cases_dry_run(self):
        case = OperationCase.objects.create(
            case_no="CASE-SLA-2",
            case_type=OperationCase.TYPE_COMPLAINT,
            priority=OperationCase.PRIORITY_LOW,
            status=OperationCase.STATUS_OPEN,
            title="Dry run overdue",
            customer=self.customer,
            created_by=self.ops,
            assigned_to=self.ops,
            sla_due_at=timezone.now() - timezone.timedelta(hours=2),
        )
        out = io.StringIO()
        call_command(
            "escalate_operation_cases",
            actor_username=self.actor.username,
            dry_run=True,
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("dry_run=True", output)
        case.refresh_from_db()
        self.assertEqual(case.status, OperationCase.STATUS_OPEN)
        self.assertFalse(TransactionMonitoringAlert.objects.filter(case=case).exists())

    def test_case_sla_escalation_run_from_operations_center(self):
        self.client.login(username="case_ops", password="pass12345")
        with patch("wallets_demo.views.call_command") as mocked_call:
            mocked_call.return_value = None
            response = self.client.post(
                reverse("operations_center"),
                {
                    "form_type": "case_sla_escalation_run",
                    "fallback_sla_hours": "24",
                    "dry_run": "on",
                },
            )
        self.assertEqual(response.status_code, 302)
        mocked_call.assert_called_once()
        args, kwargs = mocked_call.call_args
        self.assertEqual(args[0], "escalate_operation_cases")
        self.assertEqual(kwargs["actor_username"], "case_ops")
        self.assertEqual(kwargs["fallback_sla_hours"], 24)
        self.assertTrue(kwargs["dry_run"])


class BackofficeRbacUiMatrixTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.super_admin = User.objects.create_user(
            username="rbac_super_admin",
            email="rbac_super_admin@example.com",
            password="pass12345",
        )
        self.customer_service = User.objects.create_user(
            username="rbac_cs",
            email="rbac_cs@example.com",
            password="pass12345",
        )
        self.customer = User.objects.create_user(
            username="rbac_customer",
            email="rbac_customer@example.com",
            password="pass12345",
        )
        assign_roles(self.super_admin, ["super_admin"])
        assign_roles(self.customer_service, ["customer_service"])

        self.merchant = Merchant.objects.create(
            code="MRC-RBAC-1",
            name="RBAC Merchant",
            owner=self.customer_service,
            contact_email="merchant.ops@example.com",
            contact_phone="+12025551234",
            created_by=self.super_admin,
            updated_by=self.super_admin,
        )
        settlement = MerchantSettlementRecord.objects.create(
            settlement_no="STL-RBAC-1",
            merchant=self.merchant,
            currency="USD",
            period_start=timezone.localdate(),
            period_end=timezone.localdate(),
            gross_amount=Decimal("100.00"),
            fee_amount=Decimal("2.00"),
            net_amount=Decimal("98.00"),
            event_count=1,
            status=MerchantSettlementRecord.STATUS_POSTED,
            created_by=self.super_admin,
        )
        SettlementPayout.objects.create(
            settlement=settlement,
            payout_reference="PO-RBAC-1",
            amount=Decimal("98.00"),
            currency="USD",
            status=SettlementPayout.STATUS_PENDING,
            payout_channel="bank_transfer",
            destination_account="12345678901234",
            initiated_by=self.super_admin,
        )
        credential = MerchantApiCredential.objects.create(
            merchant=self.merchant,
            key_id="kid-rbac-visible",
            secret_hash=make_password("secret"),
            webhook_url="https://merchant.example.com/webhook",
            scopes_csv="wallet:read,payout:read",
            is_active=True,
            created_by=self.super_admin,
            updated_by=self.super_admin,
        )
        MerchantWebhookEvent.objects.create(
            credential=credential,
            event_type="payment.status",
            nonce="nonce-rbac-visible",
            payload_hash="abc123hash",
            signature="sig-abc",
            signature_valid=True,
            replay_detected=False,
            status="accepted",
            response_code=200,
        )

        self.case = OperationCase.objects.create(
            case_no="CASE-RBAC-1",
            case_type=OperationCase.TYPE_COMPLAINT,
            priority=OperationCase.PRIORITY_MEDIUM,
            status=OperationCase.STATUS_OPEN,
            title="RBAC case",
            description="Sensitive case description value",
            customer=self.customer,
            merchant=self.merchant,
            created_by=self.super_admin,
            assigned_to=self.customer_service,
        )
        OperationCaseNote.objects.create(
            case=self.case,
            note="Sensitive case note value",
            is_internal=True,
            created_by=self.super_admin,
        )

    def test_customer_service_ui_hides_unauthorized_forms(self):
        self.client.login(username="rbac_cs", password="pass12345")
        response = self.client.get(reverse("operations_center"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'name="form_type" value="merchant_fee_rule_upsert"')
        self.assertNotContains(response, 'name="form_type" value="merchant_api_rotate"')
        self.assertContains(response, "You do not have permission to manage merchant fee rules.")
        self.assertContains(response, "You do not have permission to rotate merchant API credentials.")

    def test_customer_service_sensitive_fields_are_masked(self):
        self.client.login(username="rbac_cs", password="pass12345")
        portal_response = self.client.get(reverse("merchant_portal"))
        self.assertEqual(portal_response.status_code, 200)
        self.assertNotContains(portal_response, "kid-rbac-visible")
        self.assertNotContains(portal_response, "nonce-rbac-visible")
        self.assertNotContains(portal_response, "12345678901234")
        self.assertContains(portal_response, "****")

        case_response = self.client.get(reverse("case_detail", kwargs={"case_id": self.case.id}))
        self.assertEqual(case_response.status_code, 200)
        self.assertNotContains(case_response, "Sensitive case description value")
        self.assertNotContains(case_response, "Sensitive case note value")

        ops_center_response = self.client.get(reverse("operations_center"))
        self.assertEqual(ops_center_response.status_code, 200)
        self.assertNotContains(ops_center_response, "Sensitive case note value")
        self.assertNotContains(ops_center_response, "kid-rbac-visible")

    def test_super_admin_can_see_sensitive_fields_and_actions(self):
        self.client.login(username="rbac_super_admin", password="pass12345")
        portal_response = self.client.get(reverse("merchant_portal"))
        self.assertEqual(portal_response.status_code, 200)
        self.assertContains(portal_response, "kid-rbac-visible")
        self.assertContains(portal_response, "nonce-rbac-visible")
        self.assertContains(portal_response, "12345678901234")
        self.assertContains(portal_response, 'name="form_type" value="merchant_portal_update_webhook"')

        case_response = self.client.get(reverse("case_detail", kwargs={"case_id": self.case.id}))
        self.assertEqual(case_response.status_code, 200)
        self.assertContains(case_response, "Sensitive case description value")
        self.assertContains(case_response, "Sensitive case note value")


class OperationsSettingsAndReportsUiTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.super_admin = User.objects.create_user(
            username="ops_super_admin",
            email="ops_super_admin@example.com",
            password="pass12345",
        )
        self.customer_service = User.objects.create_user(
            username="ops_cs",
            email="ops_cs@example.com",
            password="pass12345",
        )
        self.finance = User.objects.create_user(
            username="ops_finance",
            email="ops_finance@example.com",
            password="pass12345",
        )
        assign_roles(self.super_admin, ["super_admin"])
        assign_roles(self.customer_service, ["customer_service"])
        assign_roles(self.finance, ["finance"])

    def test_super_admin_can_view_grouped_system_settings_matrix(self):
        self.client.login(username="ops_super_admin", password="pass12345")
        response = self.client.get(reverse("operations_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Authorization Policy Matrix")
        self.assertContains(response, "Action Permissions")
        self.assertContains(response, "Field Visibility")

    def test_reports_visible_for_super_admin_and_blocked_for_customer_service(self):
        self.client.login(username="ops_super_admin", password="pass12345")
        ok_response = self.client.get(reverse("operations_reports"))
        self.assertEqual(ok_response.status_code, 200)
        self.assertContains(ok_response, "Business Operations Reports")
        self.assertContains(ok_response, "Recent Audit Trail")

        self.client.logout()
        self.client.login(username="ops_cs", password="pass12345")
        denied_response = self.client.get(reverse("operations_reports"))
        self.assertEqual(denied_response.status_code, 403)

    def test_menu_override_blocks_reports_route_even_for_backoffice_role(self):
        settings_row = OperationSetting.get_solo()
        settings_row.nav_visibility_rules = {"operations_reports": ["super_admin"]}
        settings_row.save(update_fields=["nav_visibility_rules", "updated_at"])

        self.client.login(username="ops_finance", password="pass12345")
        response = self.client.get(reverse("operations_reports"))
        self.assertEqual(response.status_code, 403)


@override_settings(MULTITENANCY_ENABLED=True, MULTITENANCY_DEFAULT_TENANT_CODE="default")
class SaaSTenantAdministrationTests(TestCase):
    def setUp(self):
        seed_role_groups()
        self.client = Client()
        self.default_tenant, _ = Tenant.objects.get_or_create(code="default", defaults={"name": "Default"})
        self.platform_admin = User.objects.create_user(
            username="saas_super",
            email="saas_super@example.com",
            password="pass12345",
            tenant=self.default_tenant,
        )
        assign_roles(self.platform_admin, ["super_admin"])

    def test_platform_admin_can_onboard_tenant(self):
        self.client.login(username="saas_super", password="pass12345")
        response = self.client.post(
            reverse("saas_onboarding"),
            {
                "tenant_code": "acme",
                "tenant_name": "ACME Wallet",
                "plan_code": "pro",
                "billing_cycle": "monthly",
                "billing_email": "billing@acme.example",
                "admin_username": "acme_admin",
                "admin_email": "admin@acme.example",
                "admin_password": "acme-pass-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        tenant = Tenant.objects.get(code="acme")
        admin = User.objects.get(username="acme_admin")
        self.assertEqual(admin.tenant_id, tenant.id)
        self.assertTrue(admin.groups.filter(name="admin").exists())
        subscription = TenantSubscription.objects.get(tenant=tenant)
        self.assertEqual(subscription.plan_code, "pro")
        self.assertEqual(subscription.status, TenantSubscription.STATUS_ACTIVE)
        self.assertTrue(
            TenantBillingEvent.objects.filter(
                tenant=tenant, event_type="tenant.onboarded"
            ).exists()
        )

    def test_tenant_admin_cannot_switch_to_other_tenant(self):
        tenant_a = Tenant.objects.create(code="ta", name="Tenant A")
        tenant_b = Tenant.objects.create(code="tb", name="Tenant B")
        admin_a = User.objects.create_user(username="ta_admin", password="pass12345", tenant=tenant_a)
        admin_b = User.objects.create_user(username="tb_admin", password="pass12345", tenant=tenant_b)
        assign_roles(admin_a, ["admin"])
        assign_roles(admin_b, ["admin"])

        self.client.login(username="ta_admin", password="pass12345")
        response = self.client.get(
            reverse("saas_tenant_admin"),
            {"tenant": "tb"},
            HTTP_X_TENANT_CODE="ta",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["tenant"].code, "ta")

        create_user_response = self.client.post(
            reverse("saas_tenant_admin"),
            {
                "form_type": "operator_create",
                "tenant_code": "tb",
                "username": "ta_operator",
                "email": "ta_operator@example.com",
                "password": "strong-pass-123",
                "role_name": "operation",
            },
            HTTP_X_TENANT_CODE="ta",
        )
        self.assertEqual(create_user_response.status_code, 302)
        created = User.objects.get(username="ta_operator")
        self.assertEqual(created.tenant_id, tenant_a.id)
        self.assertNotEqual(created.tenant_id, tenant_b.id)

    def test_usage_record_creates_daily_usage_and_billing_event(self):
        tenant = Tenant.objects.create(code="usage", name="Usage Tenant")
        record_tenant_usage(
            tenant=tenant,
            metric_code="wallet.transfer.success",
            quantity=2,
            amount=Decimal("10.50"),
            metadata={"currency": "USD"},
        )
        usage = TenantUsageDaily.objects.get(tenant=tenant, metric_code="wallet.transfer.success")
        self.assertEqual(usage.quantity, 2)
        self.assertEqual(usage.amount, Decimal("10.50"))
        self.assertTrue(
            TenantBillingEvent.objects.filter(
                tenant=tenant, event_type="usage.recorded"
            ).exists()
        )

    def test_billing_sink_is_idempotent_for_same_event_id(self):
        tenant = Tenant.objects.create(code="sink", name="Sink Tenant")
        webhook = TenantBillingWebhook.objects.create(
            tenant=tenant,
            endpoint_url="https://example.com/hook",
            signing_secret="sink-secret",
            is_active=True,
            updated_by=self.platform_admin,
        )
        payload = {
            "event_id": "evt-001",
            "tenant_code": tenant.code,
            "event_type": "invoice.generated",
            "payload": {"amount": "12.00"},
        }
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sig = hmac.new(webhook.signing_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        first = self.client.post(
            reverse("saas_billing_webhook_sink", kwargs={"tenant_code": tenant.code}),
            data=body,
            content_type="application/json",
            HTTP_X_WALLET_SIGNATURE=sig,
            HTTP_X_WALLET_EVENT="invoice.generated",
        )
        self.assertEqual(first.status_code, 202)
        second = self.client.post(
            reverse("saas_billing_webhook_sink", kwargs={"tenant_code": tenant.code}),
            data=body,
            content_type="application/json",
            HTTP_X_WALLET_SIGNATURE=sig,
            HTTP_X_WALLET_EVENT="invoice.generated",
        )
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["data"]["idempotent_replay"])
        self.assertEqual(
            TenantBillingInboundEvent.objects.filter(tenant=tenant, external_event_id="evt-001").count(),
            1,
        )

    def test_platform_admin_can_retry_failed_billing_event(self):
        tenant = Tenant.objects.create(code="retry", name="Retry Tenant")
        event = TenantBillingEvent.objects.create(
            tenant=tenant,
            event_type="invoice.generated",
            status=TenantBillingEvent.STATUS_FAILED,
            attempt_count=2,
            last_error="timeout",
        )
        self.client.login(username="saas_super", password="pass12345")
        response = self.client.post(
            reverse("saas_tenant_admin"),
            {
                "form_type": "billing_event_retry",
                "tenant_code": tenant.code,
                "event_id": event.id,
            },
        )
        self.assertEqual(response.status_code, 302)
        event.refresh_from_db()
        self.assertEqual(event.status, TenantBillingEvent.STATUS_PENDING)
        self.assertEqual(event.last_error, "")

    def test_platform_admin_can_generate_invoice(self):
        tenant = Tenant.objects.create(code="inv", name="Invoice Tenant")
        TenantSubscription.objects.create(
            tenant=tenant,
            plan_code="starter",
            status=TenantSubscription.STATUS_ACTIVE,
            monthly_base_fee=Decimal("50.00"),
            per_txn_fee=Decimal("0.1000"),
            included_txn_quota=10,
        )
        TenantUsageDaily.objects.create(
            tenant=tenant,
            usage_date=date(2026, 3, 10),
            metric_code="wallet.transfer.success",
            quantity=25,
            amount=Decimal("250.00"),
        )
        self.client.login(username="saas_super", password="pass12345")
        response = self.client.post(
            reverse("saas_tenant_admin"),
            {
                "form_type": "invoice_generate",
                "tenant_code": tenant.code,
                "invoice_year": "2026",
                "invoice_month": "3",
            },
        )
        self.assertEqual(response.status_code, 302)
        invoice = TenantInvoice.objects.get(tenant=tenant)
        self.assertEqual(invoice.status, TenantInvoice.STATUS_ISSUED)
        self.assertGreater(invoice.total_amount, Decimal("0.00"))

    @override_settings(AUTH_MODE="local")
    def test_public_self_onboarding_creates_local_admin(self):
        response = self.client.post(
            reverse("saas_self_onboarding"),
            {
                "tenant_code": "public1",
                "tenant_name": "Public One",
                "admin_email": "public1@example.com",
                "admin_username": "public1_admin",
                "admin_password": "public1-pass-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        tenant = Tenant.objects.get(code="public1")
        admin = User.objects.get(username="public1_admin")
        self.assertEqual(admin.tenant_id, tenant.id)
        self.assertTrue(admin.groups.filter(name="admin").exists())

    @override_settings(AUTH_MODE="keycloak_oidc")
    def test_public_self_onboarding_creates_claimable_sso_invite(self):
        response = self.client.post(
            reverse("saas_self_onboarding"),
            {
                "tenant_code": "sso1",
                "tenant_name": "SSO One",
                "admin_email": "sso1@example.com",
            },
        )
        self.assertEqual(response.status_code, 302)
        invite = TenantOnboardingInvite.objects.get(email="sso1@example.com")
        self.assertEqual(invite.status, TenantOnboardingInvite.STATUS_PENDING)

        user = User.objects.create_user(
            username="sso_user",
            email="sso1@example.com",
            password="pass12345",
            tenant=self.default_tenant,
        )
        claimed = claim_pending_onboarding_invite_for_user(user)
        user.refresh_from_db()
        invite.refresh_from_db()
        self.assertTrue(claimed)
        self.assertEqual(user.tenant_id, invite.tenant_id)
        self.assertTrue(user.groups.filter(name="admin").exists())
        self.assertEqual(invite.status, TenantOnboardingInvite.STATUS_CLAIMED)


class InternationalizationCoverageTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_set_language_endpoint_persists_khmer_cookie(self):
        response = self.client.post(
            reverse("set_language"),
            {"language": "km", "next": reverse("login")},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.cookies.get("django_language").value, "km")

    def test_login_page_renders_khmer_translations(self):
        response = self.client.get("/km/login/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ចូលគណនី")
        self.assertContains(response, "ចុះឈ្មោះ")
