from django import template

from wallets_demo.rbac import user_has_any_role

register = template.Library()


@register.filter(name="has_role")
def has_role(user, role_name: str):
    return user_has_any_role(user, [role_name])


@register.filter(name="has_any_role")
def has_any_role(user, role_names_csv: str):
    roles = [role.strip() for role in role_names_csv.split(",") if role.strip()]
    return user_has_any_role(user, roles)
