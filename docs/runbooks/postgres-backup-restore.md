# PostgreSQL Backup and Restore Drill

## Objective
Prove backup integrity and restore time objectives for wallet/ledger data.

## Backup Strategy
- Daily full backup.
- Point-in-time recovery (WAL archiving) enabled.
- Store encrypted backups in separate region/account.

## Backup Command (Reference)
```bash
pg_dump --format=custom --no-owner --no-acl \
  --dbname="$DATABASE_URL" \
  --file="wallet_$(date +%Y%m%d_%H%M%S).dump"
```

## Restore Drill (Staging)
1. Provision fresh Postgres instance.
2. Restore backup:
```bash
pg_restore --clean --if-exists --no-owner --no-acl \
  --dbname="$RESTORE_DATABASE_URL" wallet_<timestamp>.dump
```
3. Run service migrations.
4. Execute smoke checks:
   - Create account
   - Deposit
   - Withdraw
   - Transfer
5. Compare record counts and sample balances with source snapshot.

## RTO/RPO Tracking
- Record start/end timestamps for restore.
- Record max data loss window from WAL position.
- Keep drill report per month.

## Failover Readiness
- Document primary/replica promotion steps.
- Test application reconnection after DB endpoint switch.
