# DJ Wallet Demo System

This is a demonstration of the `dj-wallet` virtual wallet system for Django.

## Features
- User Registration & Authentication
- $100 Welcome Bonus for new users
- Dashboard with Real-time Balance
- Instant Peer-to-Peer Transfers
- Manual Deposits & Withdrawals
- Transaction History with Meta-data

## Tech Stack
- Django 6.x
- dj-wallet (Local development version)
- Vanilla CSS with Premium Design

## How to Run
1. Create a virtual environment: `python3 -m venv .venv`
2. Activate it: `source .venv/bin/activate`
3. Install dependencies: `pip install django djangorestframework -e ..`
4. Apply migrations: `python manage.py migrate`
5. Setup demo data: `python setup_dev.py`
6. Start the server: `python manage.py runserver`

## Railway Deployment (PostgreSQL)
1. From repository root, create/link a Railway project.
2. Add a PostgreSQL service.
3. Set variables:
   - `SECRET_KEY` (required)
   - `DEBUG=False`
   - `ALLOWED_HOSTS=<your-railway-domain>`
   - `CSRF_TRUSTED_ORIGINS=https://<your-railway-domain>`
4. Deploy from repo root (`Procfile` runs migrations + collectstatic + gunicorn).

## Concurrency Notes
- Database: PostgreSQL with connection pooling (PgBouncer recommended).
- App server: `gunicorn` with thread workers (`gunicorn.conf.py`).
- Data model: transaction/transfer indexes added for high write/read concurrency.
- For a real 50,000-concurrent-user target, run staged load testing and scale app/database resources based on measured latency, lock wait, and queue depth.

## Demo Accounts
- **Admin**: `admin` / `admin123`
- **Users**: `alice`, `bob`, `charlie` / `password123`
