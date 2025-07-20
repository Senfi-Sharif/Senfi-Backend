# Development Environment Configuration

## Quick Fix for HTTPS Issues

The Django development server doesn't support HTTPS. Use this configuration for development:

```bash
# Django Security Settings
DJANGO_SECRET_KEY=xxx
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0

# CORS Settings (for development)
DJANGO_CORS_ALLOW_ALL_ORIGINS=True

# Email Settings
EMAIL_SERVER=mail.senfi-sharif.ir
EMAIL_USER=admin@senfi-sharif.ir
EMAIL_PASS=xxxx

# Database (SQLite for development)
DATABASE_URL=sqlite:///./users.db

# Optional: Performance Monitoring
ENABLE_PERFORMANCE_MONITORING=True
PERFORMANCE_LOG_FILE=performance.log

# Optional: Backup Settings
BACKUP_RETENTION_DAYS=7
BACKUP_DIR=backups/

# Optional: Rate Limiting
RATE_LIMIT_ENABLED=True
LOGIN_RATE_LIMIT=5/m
EMAIL_RATE_LIMIT=3/m
```

## What Changed

The Django settings now automatically:
- **Disables HTTPS requirements** when `DEBUG=True`
- **Enables HTTPS requirements** when `DEBUG=False`
- **Ignores HTTPS environment variables** in development

## Run the Server

```bash
cd /home/arya/Documents/senfi_web/senfi_django_backend
python3 manage.py runserver 127.0.0.1:8000
```

## Production Configuration

When ready for production, use:

```bash
DJANGO_DEBUG=False
DJANGO_CORS_ALLOW_ALL_ORIGINS=False
DJANGO_CORS_ALLOWED_ORIGINS=https://yourdomain.com
DJANGO_SECURE_SSL_REDIRECT=True
DJANGO_SECURE_HSTS_SECONDS=31536000
DJANGO_SESSION_COOKIE_SECURE=True
DJANGO_CSRF_COOKIE_SECURE=True
``` 