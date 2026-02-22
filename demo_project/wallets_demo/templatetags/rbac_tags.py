from django import template

from wallets_demo.access_policy import (
    mask_sensitive_value,
    user_can_view_menu,
    user_can_view_sensitive,
    user_can_view_sensitive_domain,
)
from wallets_demo.rbac import user_has_any_role

register = template.Library()


@register.filter(name="has_role")
def has_role(user, role_name: str):
    return user_has_any_role(user, [role_name])


@register.filter(name="has_any_role")
def has_any_role(user, role_names_csv: str):
    roles = [role.strip() for role in role_names_csv.split(",") if role.strip()]
    return user_has_any_role(user, roles)


@register.filter(name="can_view_menu")
def can_view_menu(user, menu_key: str):
    return user_can_view_menu(user, menu_key)


@register.filter(name="can_view_sensitive")
def can_view_sensitive(user, _unused: str = ""):
    return user_can_view_sensitive(user)


@register.filter(name="mask_sensitive")
def mask_sensitive(value, user):
    return mask_sensitive_value(value, user)


@register.filter(name="can_view_sensitive_domain")
def can_view_sensitive_domain(user, domain_key: str):
    return user_can_view_sensitive_domain(user, domain_key)


@register.simple_tag(takes_context=True)
def sensitive_value(context, value, domain_key: str, mask: str = "****"):
    user = context.get("user")
    return mask_sensitive_value(value, user, mask=mask, domain_key=domain_key)


@register.filter(name="get_item")
def get_item(mapping, key):
    if isinstance(mapping, dict):
        return mapping.get(key)
    return None
