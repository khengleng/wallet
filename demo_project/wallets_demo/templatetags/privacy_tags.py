from django import template

register = template.Library()


@register.filter(name="mask_email")
def mask_email(value: str):
    if not value or "@" not in value:
        return value or ""
    local, domain = value.split("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{masked_local}@{domain}"


@register.filter(name="mask_phone")
def mask_phone(value: str):
    if not value:
        return ""
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) <= 4:
        return "*" * len(digits)
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


@register.filter(name="get_item")
def get_item(mapping, key):
    try:
        return mapping.get(key)
    except Exception:
        return None
