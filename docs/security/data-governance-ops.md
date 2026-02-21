# Data Governance Operations

## PII Handling

Back-office and merchant portal screens should display masked email/phone values by default.

Masking filters:

- `mask_email`
- `mask_phone`

## Retention

Operational retention is managed by:

- Operations Center retention action (`data_retention_purge`)
- CLI command: `python manage.py purge_operational_data --days 365 --dry-run`

Current policy:

- `AnalyticsEvent` and `LoginLockout` are purgeable.
- `BackofficeAuditLog` is immutable and retained.

## Access Review

SoD checks run from Operations Center (`access_review_run`) and flag users holding both maker and checker role sets.

Review records are tracked in `AccessReviewRecord` until resolved.
