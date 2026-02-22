#!/usr/bin/env python3
import os
import sys
from urllib.parse import urlparse


def _env(name: str) -> str:
    return (os.getenv(name, "") or "").strip()


def _normalize_db_signature(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port or ''}/{parsed.path.lstrip('/')}"


def main() -> int:
    mode = _env("DATABASE_ISOLATION_MODE").lower() or "compat"
    backoffice = _env("BACKOFFICE_DATABASE_URL") or _env("DATABASE_URL")
    ledger = _env("LEDGER_DATABASE_URL")
    ops_risk = _env("OPS_RISK_DATABASE_URL")
    audit_export = _env("AUDIT_EXPORT_DATABASE_URL") or _env("BACKOFFICE_DATABASE_URL")

    errors: list[str] = []
    warnings: list[str] = []

    if mode != "strict":
        warnings.append(
            f"DATABASE_ISOLATION_MODE is '{mode}', expected 'strict' for microservices isolation."
        )

    if not backoffice:
        errors.append("BACKOFFICE_DATABASE_URL (or DATABASE_URL) is required.")

    if not ledger:
        errors.append("LEDGER_DATABASE_URL is required in strict isolation mode.")

    if not ops_risk:
        errors.append("OPS_RISK_DATABASE_URL is required in strict isolation mode.")

    if not audit_export:
        errors.append(
            "AUDIT_EXPORT_DATABASE_URL (or BACKOFFICE_DATABASE_URL fallback) is required."
        )

    signatures = {}
    for name, url in (
        ("backoffice", backoffice),
        ("ledger", ledger),
        ("ops_risk", ops_risk),
    ):
        if not url:
            continue
        signatures[name] = _normalize_db_signature(url)

    if (
        "backoffice" in signatures
        and "ledger" in signatures
        and signatures["backoffice"] == signatures["ledger"]
    ):
        errors.append("BACKOFFICE_DATABASE_URL and LEDGER_DATABASE_URL must target different databases.")
    if (
        "backoffice" in signatures
        and "ops_risk" in signatures
        and signatures["backoffice"] == signatures["ops_risk"]
    ):
        errors.append("BACKOFFICE_DATABASE_URL and OPS_RISK_DATABASE_URL must target different databases.")
    if (
        "ledger" in signatures
        and "ops_risk" in signatures
        and signatures["ledger"] == signatures["ops_risk"]
    ):
        errors.append("LEDGER_DATABASE_URL and OPS_RISK_DATABASE_URL must target different databases.")

    if audit_export and backoffice:
        if _normalize_db_signature(audit_export) == _normalize_db_signature(backoffice):
            warnings.append(
                "AUDIT_EXPORT_DATABASE_URL shares backoffice DB. Allowed, but use dedicated DB for stronger isolation."
            )

    for msg in warnings:
        print(f"WARN: {msg}")

    if errors:
        for msg in errors:
            print(f"ERROR: {msg}")
        return 1

    print("OK: database isolation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
