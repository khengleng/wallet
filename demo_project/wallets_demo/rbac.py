from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from django.contrib.auth.models import Group, Permission


@dataclass(frozen=True)
class RoleDefinition:
    label: str
    permissions: tuple[tuple[str, str], ...]


ROLE_DEFINITIONS: dict[str, RoleDefinition] = {
    "super_admin": RoleDefinition(
        label="Super Admin",
        permissions=(
            ("auth", "view_user"),
            ("auth", "add_user"),
            ("auth", "change_user"),
            ("auth", "delete_user"),
            ("auth", "view_group"),
            ("auth", "change_group"),
            ("dj_wallet", "view_wallet"),
            ("dj_wallet", "change_wallet"),
            ("dj_wallet", "view_transaction"),
            ("dj_wallet", "add_transaction"),
            ("dj_wallet", "change_transaction"),
            ("dj_wallet", "view_transfer"),
            ("dj_wallet", "add_transfer"),
            ("dj_wallet", "change_transfer"),
        ),
    ),
    "admin": RoleDefinition(
        label="Admin",
        permissions=(
            ("auth", "view_user"),
            ("auth", "change_user"),
            ("dj_wallet", "view_wallet"),
            ("dj_wallet", "view_transaction"),
            ("dj_wallet", "view_transfer"),
        ),
    ),
    "finance": RoleDefinition(
        label="Finance",
        permissions=(
            ("dj_wallet", "view_wallet"),
            ("dj_wallet", "view_transaction"),
            ("dj_wallet", "add_transaction"),
            ("dj_wallet", "change_transaction"),
            ("dj_wallet", "view_transfer"),
        ),
    ),
    "customer_service": RoleDefinition(
        label="Customer Service",
        permissions=(
            ("auth", "view_user"),
            ("dj_wallet", "view_wallet"),
            ("dj_wallet", "view_transaction"),
            ("dj_wallet", "view_transfer"),
        ),
    ),
    "risk": RoleDefinition(
        label="Risk",
        permissions=(
            ("auth", "view_user"),
            ("dj_wallet", "view_wallet"),
            ("dj_wallet", "view_transaction"),
            ("dj_wallet", "view_transfer"),
        ),
    ),
    "operation": RoleDefinition(
        label="Operation",
        permissions=(
            ("auth", "view_user"),
            ("dj_wallet", "view_wallet"),
            ("dj_wallet", "view_transaction"),
        ),
    ),
    "sales": RoleDefinition(
        label="Sales",
        permissions=(
            ("auth", "view_user"),
            ("dj_wallet", "view_wallet"),
            ("dj_wallet", "view_transaction"),
        ),
    ),
}

BACKOFFICE_ROLES: tuple[str, ...] = tuple(ROLE_DEFINITIONS.keys())
MAKER_ROLES: tuple[str, ...] = ("finance", "operation", "sales")
CHECKER_ROLES: tuple[str, ...] = ("admin", "super_admin", "risk")

DEFAULT_DEMO_ROLE_ASSIGNMENTS: dict[str, tuple[str, ...]] = {
    "admin": ("super_admin",),
    "alice": ("finance",),
    "bob": ("customer_service",),
    "charlie": ("risk",),
}


def seed_role_groups() -> dict[str, list[str]]:
    missing_permissions: list[str] = []
    created_groups: list[str] = []
    updated_groups: list[str] = []

    for role_name, definition in ROLE_DEFINITIONS.items():
        group, created = Group.objects.get_or_create(name=role_name)
        permissions_to_set: list[Permission] = []
        for app_label, codename in definition.permissions:
            permission = Permission.objects.filter(
                content_type__app_label=app_label,
                codename=codename,
            ).first()
            if permission is None:
                missing_permissions.append(f"{app_label}.{codename}")
                continue
            permissions_to_set.append(permission)
        group.permissions.set(permissions_to_set)
        if created:
            created_groups.append(role_name)
        else:
            updated_groups.append(role_name)

    return {
        "created_groups": created_groups,
        "updated_groups": updated_groups,
        "missing_permissions": sorted(set(missing_permissions)),
    }


def assign_roles(user, roles: Iterable[str]) -> None:
    user.groups.clear()
    for role in roles:
        group = Group.objects.filter(name=role).first()
        if group is not None:
            user.groups.add(group)


def user_has_any_role(user, roles: Iterable[str]) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superuser", False):
        return True
    return user.groups.filter(name__in=list(roles)).exists()


def user_is_maker(user) -> bool:
    return user_has_any_role(user, MAKER_ROLES)


def user_is_checker(user) -> bool:
    return user_has_any_role(user, CHECKER_ROLES)
