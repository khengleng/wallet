# RBAC UAT Checklist (Back Office)

Use this checklist after every deployment to verify role-based visibility, action enforcement, and masking.

## Roles to validate
- `super_admin`
- `admin`
- `finance`
- `customer_service`
- `risk`
- `operation`
- `sales`
- `treasury`

## Core pages
- `/backoffice/`
- `/backoffice/operations/`
- `/backoffice/wallets/`
- `/merchant/portal/`
- `/backoffice/settlement/`
- `/backoffice/reconciliation/`
- `/backoffice/policy-hub/`
- `/backoffice/documents/`
- `/backoffice/operations-settings/`

## Required checks
1. Menu visibility
- Unauthorized menus are not rendered in sidebar.
- Authorized menus are rendered and open normally.

2. Action visibility
- Unauthorized forms/buttons are not rendered.
- Authorized forms/buttons are rendered.

3. Server-side enforcement
- Direct POST for unauthorized action returns denial and does not mutate data.
- Authorized POST executes successfully.

4. Field-level masking
- Sensitive fields are masked for unauthorized roles:
  - merchant key/webhook fields
  - webhook nonce
  - payout destination account
  - case description and case notes
- Sensitive fields are visible for authorized roles.

5. System settings
- `super_admin` can update System Setting.
- Non-`super_admin` cannot mutate System Setting.

## Automated verification
- Test suite: `wallets_demo.tests` (66 tests)
- Focused matrix tests:
  - `BackofficeRbacUiMatrixTests`
  - `CustomerCIFWalletManagementTests`

## Notes
- Policy overrides are configurable in **System Setting** via:
  - Action Permissions matrix
  - Field Visibility matrix
