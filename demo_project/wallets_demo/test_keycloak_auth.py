from django.test import SimpleTestCase, override_settings

from .keycloak_auth import map_keycloak_claims_to_rbac_roles


@override_settings(
    KEYCLOAK_ROLE_GROUP_MAP={
        "super_admin": "super_admin",
        "admin": "admin",
        "finance": "finance",
    }
)
class KeycloakRoleMappingTests(SimpleTestCase):
    def test_maps_superadmin_without_underscore(self):
        roles = map_keycloak_claims_to_rbac_roles(
            {"realm_access": {"roles": ["superadmin"]}}
        )
        self.assertIn("super_admin", roles)

    def test_maps_group_path_segment(self):
        roles = map_keycloak_claims_to_rbac_roles(
            {"groups": ["/wallet/backoffice/super-admin"]}
        )
        self.assertIn("super_admin", roles)

    def test_maps_standard_roles(self):
        roles = map_keycloak_claims_to_rbac_roles(
            {"resource_access": {"wallet-web": {"roles": ["finance", "admin"]}}}
        )
        self.assertEqual(set(roles), {"finance", "admin"})
