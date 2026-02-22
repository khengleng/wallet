# Keycloak Hardening Baseline

## Realm Security
- Enable brute-force detection and temporary lockout.
- Set short access token lifespan and reasonable refresh token lifespan.
- Require email verification for self-registration.
- Enable required actions: update password, configure OTP.

## MFA Policy
- Enforce OTP for privileged roles:
  - `super_admin`
  - `admin`
  - `finance`
  - `risk`
  - `operation`
- Keep step-up authentication for sensitive actions (maker-checker approvals, treasury disbursement).

## Session Controls
- Limit concurrent sessions per user.
- Configure idle and max session timeout.
- Revoke sessions on password reset / suspicious events.

## Client Security
- Use confidential clients for server-side apps.
- Rotate client secrets regularly.
- Restrict valid redirect URIs to exact URLs.
- Restrict web origins and CORS to trusted domains only.

## Audit and Monitoring
- Forward admin and auth events to SIEM pipeline.
- Alert on repeated login failures, admin role changes, and token errors.
- Periodically review role mappings and dormant privileged accounts.

## Automated Validation
- Run baseline checks from web service context:
  - `python manage.py check_keycloak_hardening`
  - `python manage.py check_keycloak_hardening --json`
- Fail policy:
  - command exits non-zero when baseline hardening issues are present,
  - use `--no-fail-on-issues` only for advisory/reporting mode.

## Suggested Assertion Environment Flags
To attest controls that cannot be inferred from application runtime config alone, set:
- `KEYCLOAK_ASSERT_BRUTE_FORCE_DETECTION=true`
- `KEYCLOAK_ASSERT_EMAIL_VERIFICATION=true`
- `KEYCLOAK_ASSERT_OTP_REQUIRED_FOR_PRIVILEGED=true`
- `KEYCLOAK_ASSERT_STRICT_REDIRECTS=true`
