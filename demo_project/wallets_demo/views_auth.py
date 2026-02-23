"""Auth-facing view exports (phase 1 split from monolithic views module)."""

from . import views as legacy

portal_login = legacy.portal_login
keycloak_callback = legacy.keycloak_callback
portal_logout = legacy.portal_logout
profile = legacy.profile
register = legacy.register
