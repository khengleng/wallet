# Keycloak Service

Containerized Keycloak for identity and SSO.

## Required Railway Variables
- `KC_BOOTSTRAP_ADMIN_USERNAME`
- `KC_BOOTSTRAP_ADMIN_PASSWORD`
- `KC_HEALTH_ENABLED=true`
- `KC_METRICS_ENABLED=true`

## Database (recommended for production)
- `KC_DB=postgres`
- `KC_DB_URL` (JDBC URL, e.g. `jdbc:postgresql://host:5432/dbname`)
- `KC_DB_USERNAME`
- `KC_DB_PASSWORD`

## Deploy
```bash
railway up ./services/keycloak --path-as-root -s keycloak -d
```
