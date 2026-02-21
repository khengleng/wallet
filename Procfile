web: cd demo_project && python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn demo_project_app.wsgi:application -c ../gunicorn.conf.py
