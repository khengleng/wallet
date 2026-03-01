from __future__ import annotations

from contextvars import ContextVar, Token

from .models import Tenant

_current_tenant: ContextVar[Tenant | None] = ContextVar("wallets_demo_current_tenant", default=None)


def set_current_tenant(tenant: Tenant | None) -> Token:
    return _current_tenant.set(tenant)


def get_current_tenant() -> Tenant | None:
    return _current_tenant.get()


def reset_current_tenant(token: Token) -> None:
    _current_tenant.reset(token)

