#!/bin/bash
set -e

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Starting Gunicorn server..."
exec gunicorn --bind 0.0.0.0:8000 --workers 4 senfi_django_backend.wsgi:application \
    --log-level info --access-logfile - --error-logfile - --timeout 120 --preload
