# MFA Readiness (Keycloak)

This platform is configured to use Keycloak (`AUTH_MODE=keycloak_oidc`) for primary authentication in production.  
MFA must be enforced in Keycloak flows, not in Django local auth.

## Target State

- All privileged roles (`super_admin`, `admin`, `finance`, `risk`, `treasury`, `operation`) must use MFA.
- End users should be prompted to enroll MFA at first login.
- Local Django password login should remain disabled in production.

## Keycloak Configuration Checklist

1. Realm: `wallet`
2. Authentication flow: `Browser`
3. Required execution:
   - Username Password Form
   - OTP Form (or WebAuthn)
4. OTP policy:
   - TOTP algorithm: `HmacSHA1` or stronger
   - Digits: `6`
   - Period: `30s`
   - Look-ahead window: minimal
5. Required actions:
   - `Configure OTP` enabled
6. Brute-force protection:
   - Enabled
   - Permanent lock disabled
   - Lockout threshold/window configured
7. Session hardening:
   - Short SSO idle timeout
   - Short access token lifespan
   - Refresh token reuse detection per policy

## Operational Notes

- Role propagation to app depends on Keycloak token claims and role mapping (`KEYCLOAK_ROLE_GROUP_MAP`).
- After role or MFA policy updates, users should sign out/in again to refresh session and claims.
- Keep emergency bootstrap settings disabled in production unless doing controlled break-glass recovery.

## Validation

1. Login as a privileged user and confirm OTP challenge appears.
2. Verify app access still maps correctly to expected RBAC role.
3. Verify non-privileged user behavior and fallback/recovery path.
4. Record evidence (screenshots + audit log timestamps) for security review.
