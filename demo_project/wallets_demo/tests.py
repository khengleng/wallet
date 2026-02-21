from django.test import Client, TestCase
from django.urls import reverse

from .models import ApprovalRequest, User
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
